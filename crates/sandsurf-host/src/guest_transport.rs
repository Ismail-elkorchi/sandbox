//! Shared guest I/O coordination, not another lifecycle or capture authority.
//! CaptureBoundary owns durable admission/recovery. This transport closes its
//! reusable session after active RPCs finish and excludes queued sends until
//! native recovery retires that boundary. Management loss never implies power.
use crate::guardian::{EffectOutcome, Error, GuestDriver, Result};
use crate::guest::ManagedGuestClient;
use sandsurf_native::GuestChannel;
use sandsurf_protocol::{GuestCommand, GuestServiceRequest, GuestServiceResponse, bytes_digest};
use std::sync::{
    Arc, Mutex, TryLockError,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

pub(crate) struct GuestTransport<A, C> {
    blocked: AtomicBool,
    session: Mutex<Option<(A, ManagedGuestClient<C>)>>,
}

impl<A: Clone + PartialEq, C: GuestChannel> GuestTransport<A, C> {
    pub(crate) fn new(blocked: bool) -> Self {
        Self {
            blocked: AtomicBool::new(blocked),
            session: Mutex::new(None),
        }
    }
    pub(crate) fn admissible(&self) -> bool {
        !self.blocked.load(Ordering::Acquire)
    }
    pub(crate) fn quiesce(&self) -> Result<()> {
        self.quiesce_with_timeout(Duration::from_secs(10))
    }
    fn quiesce_with_timeout(&self, timeout: Duration) -> Result<()> {
        self.blocked.store(true, Ordering::Release);
        let deadline = Instant::now() + timeout;
        loop {
            match self.session.try_lock() {
                Ok(mut session) => {
                    *session = None;
                    return Ok(());
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(Error::Protocol("guest transport lock poisoned"));
                }
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(Error::Unsupported(
                        "guest I/O has not quiesced; capture remains pending",
                    ));
                }
            }
        }
    }
    pub(crate) fn release_capture(&self) -> Result<()> {
        self.quiesce()?;
        self.blocked.store(false, Ordering::Release);
        Ok(())
    }
    pub(crate) fn reconcile_capture(
        &self,
        root: &std::path::Path,
        outcome: &sandsurf_machine::MachineOutcome,
    ) -> Result<()> {
        if crate::capture::CaptureBoundary::reconcile_transition(root, outcome)? {
            self.release_capture()?;
        }
        Ok(())
    }
    fn with_binding<T>(
        &self,
        active: Option<A>,
        create: fn(&A) -> ManagedGuestClient<C>,
        operation: impl FnOnce(&mut ManagedGuestClient<C>) -> T,
    ) -> Option<T> {
        if !self.admissible() {
            return None;
        }
        let mut cache = self.session.lock().ok()?;
        // Recheck inside the active-RPC lock: capture may have closed admission
        // while this caller waited. No native pause can race a newly sent RPC.
        if !self.admissible() {
            return None;
        }
        let Some(active) = active else {
            *cache = None;
            return None;
        };
        if cache.as_ref().is_none_or(|(cached, _)| cached != &active) {
            *cache = Some((active.clone(), create(&active)));
        }
        Some(operation(&mut cache.as_mut()?.1))
    }
    pub(crate) fn driver(
        self: &Arc<Self>,
        active: Arc<Mutex<Option<A>>>,
        create: fn(&A) -> ManagedGuestClient<C>,
    ) -> Box<dyn GuestDriver>
    where
        A: Send + 'static,
        C: Send + 'static,
    {
        Box::new(CachedGuest {
            active,
            transport: Arc::clone(self),
            create,
        })
    }
}

struct CachedGuest<A, C> {
    active: Arc<Mutex<Option<A>>>,
    transport: Arc<GuestTransport<A, C>>,
    create: fn(&A) -> ManagedGuestClient<C>,
}
impl<A: Clone + PartialEq, C: GuestChannel> CachedGuest<A, C> {
    fn with_driver<T>(&self, operation: impl FnOnce(&mut ManagedGuestClient<C>) -> T) -> Option<T> {
        let active = self.active.lock().ok()?.clone();
        self.transport.with_binding(active, self.create, operation)
    }
}
impl<A: Clone + PartialEq + Send, C: GuestChannel + Send> GuestDriver for CachedGuest<A, C> {
    fn dispatch(&mut self, command: &GuestCommand) -> EffectOutcome {
        self.with_driver(|driver| driver.dispatch(command))
            .unwrap_or_else(|| {
                EffectOutcome::NotApplied(bytes_digest(b"guest-management-not-dispatched"))
            })
    }
    fn poll(
        &mut self,
        hints: &crate::guest_worker::ExecutionHints,
    ) -> Result<crate::guest_worker::GuestPoll> {
        self.with_driver(|driver| driver.poll(hints))
            .ok_or(Error::Unsupported("guest management unavailable"))?
    }
    fn query(&mut self, request: GuestServiceRequest) -> Result<GuestServiceResponse> {
        self.with_driver(|driver| driver.query(request))
            .ok_or(Error::Unsupported("guest management unavailable"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::GuestClient;
    use sandsurf_native::{GuestChannelError, GuestConnection};
    use std::sync::mpsc;

    struct NoChannel;
    impl GuestChannel for NoChannel {
        fn connect(&mut self) -> std::result::Result<Box<dyn GuestConnection>, GuestChannelError> {
            panic!("transport coordination tests never connect to a guest");
        }
    }
    fn client(generation: &u64) -> ManagedGuestClient<NoChannel> {
        ManagedGuestClient::new(
            GuestClient::new(
                NoChannel,
                "transport".try_into().unwrap(),
                (*generation).try_into().unwrap(),
                bytes_digest(b"boot"),
                [1; 32],
            ),
            None,
        )
    }
    #[test]
    fn capture_drains_active_rpc_and_excludes_queued_sends() {
        let transport = Arc::new(GuestTransport::new(false));
        let (entered, entry) = mpsc::channel();
        let (finish, finished) = mpsc::channel();
        let active = Arc::new(Mutex::new(Some(1)));
        let worker_transport = Arc::clone(&transport);
        let worker_active = Arc::clone(&active);
        let worker = std::thread::spawn(move || {
            let driver = CachedGuest {
                active: worker_active,
                transport: worker_transport,
                create: client,
            };
            driver.with_driver(|_| {
                entered.send(()).unwrap();
                finished.recv_timeout(Duration::from_secs(5)).unwrap();
            })
        });
        entry.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            active.try_lock().is_ok(),
            "native binding must not be locked across guest I/O"
        );
        let capture_transport = Arc::clone(&transport);
        let (quiesced, quiescence) = mpsc::channel();
        let capture = std::thread::spawn(move || {
            capture_transport.quiesce().unwrap();
            quiesced.send(()).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while transport.admissible() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(
            quiescence.try_recv().is_err(),
            "capture must await the active RPC"
        );
        assert!(
            transport
                .with_binding(Some(1), client, |_| panic!("queued send during capture"))
                .is_none()
        );
        finish.send(()).unwrap();
        assert!(worker.join().unwrap().is_some());
        quiescence.recv_timeout(Duration::from_secs(5)).unwrap();
        capture.join().unwrap();
        assert!(transport.session.lock().unwrap().is_none());
        transport.release_capture().unwrap();
        assert_eq!(transport.with_binding(Some(1), client, |_| 42), Some(42));
        transport.quiesce().unwrap();
        assert!(transport.session.lock().unwrap().is_none());
    }
    #[test]
    fn interrupted_capture_starts_closed_and_stale_bindings_do_not_reuse_sessions() {
        let transport = GuestTransport::new(true);
        assert!(
            transport
                .with_binding(Some(1), client, |_| panic!("sent before recovery"))
                .is_none()
        );
        transport.release_capture().unwrap();
        assert_eq!(transport.with_binding(Some(1), client, |_| 7), Some(7));
        assert_eq!(transport.session.lock().unwrap().as_ref().unwrap().0, 1);
        assert_eq!(transport.with_binding(Some(2), client, |_| 8), Some(8));
        assert_eq!(transport.session.lock().unwrap().as_ref().unwrap().0, 2);
        assert!(
            transport
                .with_binding(None, client, |_| panic!("sent with no binding"))
                .is_none()
        );
        assert!(transport.session.lock().unwrap().is_none());
    }
    #[test]
    fn slow_io_cannot_indefinitely_block_native_capture_control() {
        let transport = GuestTransport::<u64, NoChannel>::new(false);
        let session = transport.session.lock().unwrap();
        assert!(
            transport
                .quiesce_with_timeout(Duration::from_millis(2))
                .is_err()
        );
        assert!(!transport.admissible());
        drop(session);
        transport.release_capture().unwrap();
        assert!(transport.admissible());
    }
}
