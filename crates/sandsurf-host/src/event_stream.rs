//! A read-only journal transport, not another journal or lifecycle owner.
//! Each connection has one page of credit. Idle connections wake on committed
//! cursor advancement; heartbeats bound detection of disconnected observers.

use super::*;
use sandsurf_native::local::LocalConnection;
use std::sync::{Condvar, Mutex};

const HEARTBEAT: Duration = Duration::from_secs(10);
const STREAM_TIMEOUT: Duration = Duration::from_secs(30);
// Keep ingress capacity available for machine control and ordinary queries.
const MAX_STREAMS: usize = 8;

struct SignalState {
    cursor: Counter,
    closed: bool,
    active: usize,
}

pub(super) struct EventSignal {
    state: Mutex<SignalState>,
    changed: Condvar,
}

impl EventSignal {
    pub(super) fn new(cursor: Counter) -> Self {
        Self {
            state: Mutex::new(SignalState {
                cursor,
                closed: false,
                active: 0,
            }),
            changed: Condvar::new(),
        }
    }

    pub(super) fn publish(&self, cursor: Counter) {
        let mut state = self.state.lock().expect("event notification poisoned");
        if cursor != state.cursor {
            state.cursor = cursor;
            self.changed.notify_all();
        }
    }

    pub(super) fn close(&self) {
        self.state
            .lock()
            .expect("event notification poisoned")
            .closed = true;
        self.changed.notify_all();
    }

    fn wait(&self, after: Counter, timeout: Duration) -> bool {
        let state = self.state.lock().expect("event notification poisoned");
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| {
                !state.closed && state.cursor <= after
            })
            .expect("event notification poisoned");
        !state.closed
    }

    fn acquire(self: &Arc<Self>) -> Result<StreamLease> {
        let mut state = self.state.lock().expect("event notification poisoned");
        if state.closed || state.active >= MAX_STREAMS {
            return Err(Error::Rejected {
                category: "capacity".into(),
                message: "guardian event stream capacity unavailable".into(),
            });
        }
        state.active += 1;
        Ok(StreamLease(Arc::clone(self)))
    }
}

struct StreamLease(Arc<EventSignal>);
impl Drop for StreamLease {
    fn drop(&mut self) {
        self.0
            .state
            .lock()
            .expect("event notification poisoned")
            .active -= 1;
    }
}

pub(super) fn serve(
    connection: &mut LocalConnection,
    owner: &mpsc::SyncSender<GuardianIngress>,
    events: &Arc<EventSignal>,
    machine_id: MachineId,
    mut after: Counter,
    maximum: u16,
) -> Result<()> {
    let lease = if maximum == 0 || maximum > 256 {
        Err(Error::Protocol("event page must contain 1..256 entries"))
    } else {
        events.acquire()
    };
    let _lease = match lease {
        Ok(lease) => lease,
        Err(error) => {
            connection.write_frame(
                &response_frame(Counter::ONE, &rejected(error))?,
                STREAM_TIMEOUT,
            )?;
            return Ok(());
        }
    };
    loop {
        let (reply, response) = mpsc::channel();
        owner
            .try_send(GuardianIngress::Request {
                parsed: Box::new(Ok(GuardianRequest::Runtime {
                    machine_id: machine_id.clone(),
                    request: RuntimeRequest::Events { after, maximum },
                })),
                reply,
            })
            .map_err(|_| Error::Protocol("guardian observer queue unavailable"))?;
        let response = response
            .recv()
            .map_err(|_| Error::Protocol("guardian owner stopped"))?;
        let page = match &response {
            GuardianResponse::Runtime {
                response: RuntimeResponse::Events { page },
            } => Some(page),
            _ => None,
        };
        let frame = match response_frame(Counter::ONE, &response) {
            Ok(frame) => frame,
            Err(error) => {
                connection.write_frame(
                    &response_frame(Counter::ONE, &rejected(error))?,
                    STREAM_TIMEOUT,
                )?;
                return Ok(());
            }
        };
        connection.write_frame(&frame, STREAM_TIMEOUT)?;
        let Some(page) = page else {
            return Ok(());
        };
        after = page.cursor;
        let Some(credit) = connection.read_frame(STREAM_TIMEOUT)? else {
            return Ok(());
        };
        let credit = parse_request(credit)?
            .assemble(None)
            .map_err(|_| Error::Protocol("invalid event stream credit"))?;
        if credit
            != (GuardianRequest::SubscribeEvents {
                machine_id: machine_id.clone(),
                after,
                maximum,
            })
        {
            return Err(Error::Protocol(
                "event stream credit differs from delivered boundary",
            ));
        }
        if after == page.available && !events.wait(after, HEARTBEAT) {
            return Ok(());
        }
    }
}

/// The cursor advances only after a complete page has been decoded. A caller
/// can reconnect using that cursor; no command or input bytes are replayed.
pub struct EventStream {
    connection: LocalConnection,
    machine_id: MachineId,
    after: Counter,
    maximum: u16,
    credit_due: bool,
}

impl EventStream {
    pub fn open(
        endpoint: &Path,
        machine_id: MachineId,
        after: Counter,
        maximum: u16,
    ) -> Result<Self> {
        if maximum == 0 || maximum > 256 {
            return Err(Error::Protocol("event page must contain 1..256 entries"));
        }
        let mut stream = Self {
            connection: LocalConnection::connect(endpoint, STREAM_TIMEOUT)?,
            machine_id,
            after,
            maximum,
            credit_due: false,
        };
        stream.credit()?;
        Ok(stream)
    }

    fn credit(&mut self) -> Result<()> {
        let (wire, _) = RequestEnvelope::split(GuardianRequest::SubscribeEvents {
            machine_id: self.machine_id.clone(),
            after: self.after,
            maximum: self.maximum,
        })
        .map_err(|_| Error::Protocol("invalid event stream credit"))?;
        self.connection
            .write_frame(&request_frame(&wire)?, STREAM_TIMEOUT)?;
        Ok(())
    }

    pub fn read_page(&mut self) -> Result<RuntimeEventPage> {
        if self.credit_due {
            self.credit()?;
        }
        let frame = self
            .connection
            .read_frame(STREAM_TIMEOUT)?
            .ok_or(Error::Protocol("event stream closed"))?;
        match parse_response(frame)? {
            GuardianResponse::Runtime {
                response: RuntimeResponse::Events { page },
            } => {
                let mut cursor = self.after;
                for event in &page.events {
                    cursor = cursor
                        .next()
                        .map_err(|_| Error::Protocol("event cursor overflow"))?;
                    if event.cursor != cursor
                        || runtime_event_digest(&self.machine_id, cursor, &event.value)
                            .map_err(|_| Error::Protocol("event stream digest input invalid"))?
                            != event.digest
                    {
                        return Err(Error::Protocol(
                            "event stream history coverage or digest mismatch",
                        ));
                    }
                }
                if page.events.len() > usize::from(self.maximum)
                    || cursor != page.cursor
                    || page.cursor > page.available
                {
                    return Err(Error::Protocol("event stream page boundary mismatch"));
                }
                self.after = cursor;
                self.credit_due = true;
                Ok(page)
            }
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
            _ => Err(Error::Protocol(
                "event stream returned a non-event response",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_do_not_lose_commits_before_wait_and_shutdown_wakes_observers() {
        let signal = Arc::new(EventSignal::new(Counter::ZERO));
        signal.publish(Counter::ONE);
        assert!(signal.wait(Counter::ZERO, Duration::from_secs(1)));
        let waiting = Arc::clone(&signal);
        let thread =
            std::thread::spawn(move || waiting.wait(Counter::ONE, Duration::from_secs(30)));
        signal.close();
        assert!(!thread.join().unwrap());
    }

    #[test]
    fn stream_capacity_is_bounded_and_leaves_control_slots_available() {
        let signal = Arc::new(EventSignal::new(Counter::ZERO));
        let leases = (0..MAX_STREAMS)
            .map(|_| signal.acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(signal.acquire().is_err());
        drop(leases);
        assert!(signal.acquire().is_ok());
        signal.close();
        assert!(signal.acquire().is_err());
    }
}
