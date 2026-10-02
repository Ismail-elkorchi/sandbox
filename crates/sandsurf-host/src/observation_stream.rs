//! Shared read-only event/console transport, not another retention or lifecycle owner.
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
    revision: u64,
    closed: bool,
    active: usize,
}

pub(crate) struct ObservationSignal {
    state: Mutex<SignalState>,
    changed: Condvar,
}

impl ObservationSignal {
    pub(crate) fn new(cursor: Counter) -> Self {
        Self {
            state: Mutex::new(SignalState {
                cursor,
                revision: 0,
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
            state.revision = state.revision.wrapping_add(1);
            self.changed.notify_all();
        }
    }

    pub(crate) fn notify(&self) {
        let mut state = self
            .state
            .lock()
            .expect("observation notification poisoned");
        state.revision = state.revision.wrapping_add(1);
        self.changed.notify_all();
    }

    fn revision(&self) -> u64 {
        self.state
            .lock()
            .expect("observation notification poisoned")
            .revision
    }

    fn wait_revision(&self, revision: u64) -> bool {
        let state = self
            .state
            .lock()
            .expect("observation notification poisoned");
        let (state, _) = self
            .changed
            .wait_timeout_while(state, HEARTBEAT, |state| {
                !state.closed && state.revision == revision
            })
            .expect("observation notification poisoned");
        !state.closed
    }

    pub(super) fn close(&self) {
        self.state
            .lock()
            .expect("observation notification poisoned")
            .closed = true;
        self.changed.notify_all();
    }

    fn acquire(self: &Arc<Self>) -> Result<StreamLease> {
        let mut state = self.state.lock().expect("event notification poisoned");
        if state.closed || state.active >= MAX_STREAMS {
            return Err(Error::Rejected {
                category: "capacity".into(),
                message: "guardian observation stream capacity unavailable".into(),
            });
        }
        state.active += 1;
        Ok(StreamLease(Arc::clone(self)))
    }
}

struct StreamLease(Arc<ObservationSignal>);
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
    events: &Arc<ObservationSignal>,
    mut subscription: GuardianRequest,
) -> Result<()> {
    let lease = query(&subscription).and_then(|_| events.acquire());
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
        // Capture the notification revision before reading the durable owner;
        // a commit between that read and waiting cannot be lost.
        let revision = events.revision();
        let (reply, response) = mpsc::channel();
        owner
            .try_send(GuardianIngress::Request {
                parsed: Box::new(Ok(query(&subscription)?)),
                reply,
            })
            .map_err(|_| Error::Protocol("guardian observer queue unavailable"))?;
        let response = response
            .recv()
            .map_err(|_| Error::Protocol("guardian owner stopped"))?;
        let boundary = advance(&mut subscription, &response)?;
        let (response, binary) = response
            .into_wire_parts()
            .map_err(|_| Error::Protocol("invalid observation bytes"))?;
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
        if let Some(binary) = binary {
            send_binary(
                &mut crate::ipc_frames::LocalFrameChannel {
                    connection,
                    timeout: STREAM_TIMEOUT,
                },
                binary,
            )?;
        }
        let Some((idle, complete)) = boundary else {
            return Ok(());
        };
        if complete {
            return Ok(());
        }
        let Some(credit) = connection.read_frame(STREAM_TIMEOUT)? else {
            return Ok(());
        };
        let credit = parse_request(credit)?
            .assemble(None)
            .map_err(|_| Error::Protocol("invalid observation stream credit"))?;
        if credit != subscription {
            return Err(Error::Protocol(
                "observation stream credit differs from delivered boundary",
            ));
        }
        if idle && !events.wait_revision(revision) {
            return Ok(());
        }
    }
}

fn query(subscription: &GuardianRequest) -> Result<GuardianRequest> {
    let (machine_id, request) = match subscription {
        GuardianRequest::SubscribeEvents {
            machine_id,
            after,
            maximum,
        } if *maximum != 0 && *maximum <= 256 => (
            machine_id,
            RuntimeRequest::Events {
                after: *after,
                maximum: *maximum,
            },
        ),
        GuardianRequest::SubscribeConsole {
            machine_id,
            generation,
            after,
            maximum,
        } if *generation != Counter::ZERO
            && *maximum != 0
            && *maximum as usize <= MAX_CONSOLE_PAGE_BYTES =>
        {
            (
                machine_id,
                RuntimeRequest::ReadConsole {
                    generation: *generation,
                    after: *after,
                    maximum: *maximum,
                },
            )
        }
        _ => return Err(Error::Protocol("invalid observation subscription")),
    };
    Ok(GuardianRequest::Runtime {
        machine_id: machine_id.clone(),
        request,
    })
}

fn advance(
    subscription: &mut GuardianRequest,
    response: &GuardianResponse,
) -> Result<Option<(bool, bool)>> {
    match (subscription, response) {
        (
            GuardianRequest::SubscribeEvents {
                machine_id,
                after,
                maximum,
            },
            GuardianResponse::Runtime {
                response: RuntimeResponse::Events { page },
            },
        ) => {
            let mut cursor = *after;
            for event in &page.events {
                cursor = cursor
                    .next()
                    .map_err(|_| Error::Protocol("event cursor overflow"))?;
                if event.cursor != cursor
                    || runtime_event_digest(machine_id, cursor, &event.value)
                        .map_err(|_| Error::Protocol("event digest input"))?
                        != event.digest
                {
                    return Err(Error::Protocol("event history coverage or digest mismatch"));
                }
            }
            if page.events.len() > usize::from(*maximum)
                || cursor != page.cursor
                || cursor > page.available
            {
                return Err(Error::Protocol("event page boundary mismatch"));
            }
            *after = cursor;
            Ok(Some((cursor == page.available, false)))
        }
        (
            GuardianRequest::SubscribeConsole {
                generation,
                after,
                maximum,
                ..
            },
            GuardianResponse::Runtime {
                response: RuntimeResponse::Console { page },
            },
        ) => {
            let end = after
                .get()
                .checked_add(page.bytes.len() as u64)
                .ok_or(Error::Protocol("console cursor overflow"))?;
            if page.generation != *generation
                || page.after != *after
                || page.bytes.len() > *maximum as usize
                || page.cursor > page.available
                || match &page.loss {
                    Some(loss) => {
                        loss.from.get() != end || loss.to != page.cursor || loss.from >= loss.to
                    }
                    None => end != page.cursor.get(),
                }
            {
                return Err(Error::Protocol("console stream coverage mismatch"));
            }
            *after = page.cursor;
            Ok(Some((
                page.cursor == page.available,
                (!page.open || page.capture_failed) && page.cursor == page.available,
            )))
        }
        (_, GuardianResponse::Rejected { .. }) => Ok(None),
        _ => Err(Error::Protocol("observation stream response kind mismatch")),
    }
}

/// The cursor advances only after a complete page has been decoded. A caller
/// can reconnect using that cursor; no command or input bytes are replayed.
pub struct ObservationStream {
    connection: LocalConnection,
    subscription: GuardianRequest,
    credit_due: bool,
}

impl ObservationStream {
    pub fn open(endpoint: &Path, subscription: GuardianRequest) -> Result<Self> {
        query(&subscription)?;
        let mut stream = Self {
            connection: LocalConnection::connect(endpoint, STREAM_TIMEOUT)?,
            subscription,
            credit_due: false,
        };
        stream.credit()?;
        Ok(stream)
    }

    fn credit(&mut self) -> Result<()> {
        let (wire, _) = RequestEnvelope::split(self.subscription.clone())
            .map_err(|_| Error::Protocol("invalid observation stream credit"))?;
        self.connection
            .write_frame(&request_frame(&wire)?, STREAM_TIMEOUT)?;
        Ok(())
    }

    pub fn read_page(&mut self) -> Result<RuntimeResponse> {
        if self.credit_due {
            self.credit()?;
        }
        let frame = self
            .connection
            .read_frame(STREAM_TIMEOUT)?
            .ok_or(Error::Protocol("observation stream closed"))?;
        let mut response = parse_response(frame)?;
        if let Some(metadata) = response
            .binary_descriptor()
            .map_err(|_| Error::Protocol("invalid observation metadata"))?
        {
            let binary = receive_binary(
                &mut crate::ipc_frames::LocalFrameChannel {
                    connection: &mut self.connection,
                    timeout: STREAM_TIMEOUT,
                },
                &metadata,
                MAX_RPC_DATA_BYTES,
            )?;
            response = response
                .with_wire_bytes(binary)
                .map_err(|_| Error::Protocol("invalid observation bytes"))?;
        }
        advance(&mut self.subscription, &response)?;
        match response {
            GuardianResponse::Runtime { response } => {
                self.credit_due = true;
                Ok(response)
            }
            GuardianResponse::Rejected { category, message } => {
                Err(Error::Rejected { category, message })
            }
            _ => Err(Error::Protocol(
                "observation stream returned a non-observation response",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_do_not_lose_commits_before_wait_and_shutdown_wakes_observers() {
        let signal = Arc::new(ObservationSignal::new(Counter::ZERO));
        let revision = signal.revision();
        signal.notify();
        assert!(signal.wait_revision(revision));
        signal.publish(Counter::ONE);
        assert!(signal.wait_revision(revision));
        let revision = signal.revision();
        let waiting = Arc::clone(&signal);
        let thread = std::thread::spawn(move || waiting.wait_revision(revision));
        signal.close();
        assert!(!thread.join().unwrap());
    }

    #[test]
    fn console_credit_covers_binary_and_loss_and_drains_closed_history() {
        let mut subscription = GuardianRequest::SubscribeConsole {
            machine_id: "computer".try_into().unwrap(),
            generation: Counter::ONE,
            after: Counter::ZERO,
            maximum: 2,
        };
        let response = |after, cursor, bytes, loss| GuardianResponse::Runtime {
            response: RuntimeResponse::Console {
                page: sandsurf_protocol::ConsolePage {
                    generation: Counter::ONE,
                    after,
                    cursor,
                    available: Counter::try_from(4).unwrap(),
                    bytes,
                    loss,
                    open: false,
                    capture_failed: false,
                },
            },
        };
        let first = response(
            Counter::ZERO,
            Counter::try_from(2).unwrap(),
            vec![0, 255],
            None,
        );
        assert_eq!(
            advance(&mut subscription, &first).unwrap(),
            Some((false, false))
        );
        assert!(
            advance(&mut subscription, &first).is_err(),
            "a repeated page cannot cover a new credit"
        );
        let last = response(
            Counter::try_from(2).unwrap(),
            Counter::try_from(4).unwrap(),
            vec![],
            Some(sandsurf_protocol::ConsoleLoss {
                from: Counter::try_from(2).unwrap(),
                to: Counter::try_from(4).unwrap(),
            }),
        );
        assert_eq!(
            advance(&mut subscription, &last).unwrap(),
            Some((true, true))
        );
    }

    #[test]
    fn stream_capacity_is_bounded_and_leaves_control_slots_available() {
        let signal = Arc::new(ObservationSignal::new(Counter::ZERO));
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
