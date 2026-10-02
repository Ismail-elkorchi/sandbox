//! Private QEMU control for guardian-owned hardware-accelerated VM processes.
//! QMP observations do not admit host authority or prove guest cooperation.
pub use crate::qemu_launch::{Accelerator, LaunchConfig};
#[cfg(any(target_os = "macos", windows, test))]
pub use control::{PartitionUsage, PowerEvents, QemuControl};

#[cfg(any(target_os = "macos", windows, test))]
mod control {
    use sandsurf_native::GuestConnection;
    use sandsurf_native::socket_io::SocketConnection;
    use sandsurf_protocol::{Counter, Digest, bytes_digest};
    use serde_json::{Value, json};
    use std::io::{self, BufRead, BufReader, Write};
    use std::path::Path;
    use std::time::{Duration, Instant};

    const MAX_MESSAGE: usize = 64 * 1024;
    const MAX_EVENTS_PER_RESPONSE: usize = 256;

    /// Consumed native events. Unavailable control never establishes stopped power.
    #[derive(Default)]
    pub struct PowerEvents {
        pub guest_reset: Option<Digest>,
        pub shutdown: Option<Digest>,
        pub failed: Option<Digest>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
    #[serde(rename_all = "kebab-case", deny_unknown_fields)]
    pub struct PartitionUsage {
        pub total_runtime_micros: Counter,
        pub hypervisor_runtime_micros: Counter,
        pub virtual_processors: u32,
    }

    pub struct QemuControl {
        stream: BufReader<SocketConnection>,
        sequence: Counter,
        events: PowerEvents,
        timeout: Duration,
        partial_message: Vec<u8>,
        pending_response: Option<u64>,
        pending_events: usize,
        poisoned: bool,
    }

    impl QemuControl {
        pub(crate) fn open(stream: SocketConnection, timeout: Duration) -> io::Result<Self> {
            if timeout.is_zero() || timeout > Duration::from_secs(120) {
                return Err(invalid("QMP deadline exceeds native bound"));
            }
            let mut control = Self {
                stream: BufReader::with_capacity(8192, stream),
                sequence: Counter::ZERO,
                events: PowerEvents::default(),
                timeout,
                partial_message: Vec::with_capacity(1024),
                pending_response: None,
                pending_events: 0,
                poisoned: false,
            };
            let greeting = control.read_message(Instant::now() + timeout)?;
            if !greeting["QMP"]["version"]["qemu"].is_object()
                || !greeting["QMP"]["capabilities"].is_array()
            {
                return Err(invalid("invalid QMP greeting"));
            }
            control.execute("qmp_capabilities", json!({}))?;
            Ok(control)
        }

        /// Issue only native owner commands; no arbitrary monitor/shell interface.
        pub fn status(&mut self) -> io::Result<String> {
            let value = self.execute_for(
                "query-status",
                json!({}),
                self.timeout.min(Duration::from_millis(250)),
            )?;
            let status = value["status"]
                .as_str()
                .ok_or_else(|| invalid("QMP power observation has no status"))?;
            if status.len() > 64 || value["running"].as_bool() != Some(status == "running") {
                return Err(invalid("invalid QMP power observation"));
            }
            Ok(status.to_owned())
        }

        pub fn pause(&mut self) -> io::Result<()> {
            self.execute("stop", json!({}))?;
            if self.status()? != "paused" {
                return Err(invalid("QEMU did not observe paused power"));
            }
            Ok(())
        }

        /// Original WHP partition counters, not guest management or Job estimates.
        /// Failure leaves the measurement unavailable and says nothing about power.
        pub fn partition_usage(&mut self) -> io::Result<PartitionUsage> {
            let value = self.execute_for(
                "query-sandsurf-partition-counters",
                json!({}),
                self.timeout.min(Duration::from_millis(250)),
            )?;
            let value: PartitionUsage = serde_json::from_value(value).map_err(io::Error::other)?;
            if !(1..=32).contains(&value.virtual_processors) {
                return Err(invalid("native partition CPU inventory exceeds bound"));
            }
            Ok(value)
        }

        pub fn resume(&mut self) -> io::Result<()> {
            self.execute("cont", json!({}))?;
            if self.status()? != "running" {
                return Err(invalid("QEMU did not observe running power"));
            }
            Ok(())
        }

        pub fn quit(&mut self) -> io::Result<()> {
            self.execute("quit", json!({})).map(|_| ())
        }

        /// Native paused-state capture. File transport is structured, not an exec
        /// URI or monitor command. The host storage owner supplies a protected
        /// staging file on its bounded volume and verifies it before publication.
        pub fn save_state(&mut self, destination: &Path) -> io::Result<()> {
            if self.status()? != "paused" {
                return Err(invalid("full capture requires a native paused boundary"));
            }
            self.execute("migrate", file_channel(destination)?)?;
            self.wait_migration()?;
            if !matches!(self.status()?.as_str(), "postmigrate" | "paused") {
                return Err(invalid(
                    "capture did not retain a native stopped-CPU boundary",
                ));
            }
            Ok(())
        }

        /// The owner must start with -incoming defer and native CPU execution
        /// disabled. Restored state is still paused when this returns; the current
        /// external policy is applied independently before an explicit resume.
        pub fn load_state(&mut self, source: &Path) -> io::Result<()> {
            if self.status()? != "inmigrate" {
                return Err(invalid("restore requires a deferred native incoming owner"));
            }
            self.execute("migrate-incoming", file_channel(source)?)?;
            self.wait_migration()?;
            if self.status()? != "paused" {
                return Err(invalid("restored machine did not remain paused"));
            }
            Ok(())
        }

        fn wait_migration(&mut self) -> io::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                let remaining =
                    deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "native state transfer deadline exceeded",
                            )
                        })?;
                let result =
                    self.execute_for("query-migrate", json!({}), remaining.min(self.timeout))?;
                match result["status"].as_str() {
                    Some("completed") => return Ok(()),
                    Some("setup" | "active" | "device") => {}
                    Some("failed" | "cancelled") => {
                        return Err(invalid("native state transfer failed"));
                    }
                    _ => return Err(invalid("native state transfer has no definite status")),
                }
                // One admitted synchronous capture, not the SDK observation hot
                // path. Bound native progress checks without a CPU-burning loop.
                std::thread::sleep(remaining.min(Duration::from_millis(20)));
            }
        }

        pub fn take_power_events(&mut self) -> PowerEvents {
            std::mem::take(&mut self.events)
        }

        /// Call only after the retained native child has exited. A final reset
        /// event can already be buffered when QEMU closes its socket; sending a
        /// new query first can lose it to EPIPE. This never establishes native
        /// exit by itself, and never treats incomplete control as guest shutdown.
        pub fn drain_exit_events(&mut self) -> io::Result<()> {
            let deadline = Instant::now() + Duration::from_millis(250);
            for _ in 0..=MAX_EVENTS_PER_RESPONSE {
                match self.read_message(deadline) {
                    Err(error)
                        if error.kind() == io::ErrorKind::UnexpectedEof
                            && self.partial_message.is_empty() =>
                    {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                    Ok(response) if self.record_event(&response)? => {}
                    Ok(response)
                        if self.pending_response.is_some()
                            && response["id"].as_u64() == self.pending_response =>
                    {
                        self.pending_response = None;
                    }
                    Ok(_) => return Err(invalid("unsolicited QMP response at native exit")),
                }
            }
            Err(invalid("final QMP event stream exceeds native bound"))
        }

        fn record_event(&mut self, response: &Value) -> io::Result<bool> {
            let Some(name) = response["event"].as_str() else {
                return Ok(false);
            };
            let evidence = bytes_digest(&serde_json::to_vec(response).map_err(io::Error::other)?);
            match name {
                "SHUTDOWN" => {
                    if response["data"]["guest"] == true
                        && response["data"]["reason"] == "guest-reset"
                    {
                        self.events.guest_reset = Some(evidence.clone());
                    }
                    self.events.shutdown = Some(evidence);
                }
                "GUEST_PANICKED" | "BLOCK_IO_ERROR" => self.events.failed = Some(evidence),
                _ => {}
            }
            Ok(true)
        }

        fn execute(&mut self, command: &str, arguments: Value) -> io::Result<Value> {
            self.execute_for(command, arguments, self.timeout)
        }

        fn execute_for(
            &mut self,
            command: &str,
            arguments: Value,
            timeout: Duration,
        ) -> io::Result<Value> {
            let deadline = Instant::now() + timeout;
            if self.poisoned {
                return Err(invalid(
                    "QMP session requires a fresh owned-process connection",
                ));
            }
            // A timeout is not a framing boundary. Drain a late response under
            // its original id before sending anything new, and never expose that
            // old response as a current power/postcondition observation.
            if let Some(id) = self.pending_response {
                self.read_response(id, deadline)?;
            }
            self.sequence = self.sequence.next().map_err(io::Error::other)?;
            let id = self.sequence.get();
            self.set_deadline(deadline)?;
            let mut bytes = serde_json::to_vec(
                &json!({ "execute": command, "arguments": arguments, "id": id }),
            )
            .map_err(io::Error::other)?;
            bytes.push(b'\n');
            if let Err(error) = self.stream.get_mut().write_all(&bytes) {
                // A partially written request cannot be repaired by appending a
                // new command. A replacement channel must still target the same
                // retained native child; it must never replace the Linux machine.
                self.poisoned = true;
                return Err(error);
            }
            self.pending_response = Some(id);
            self.pending_events = 0;
            self.read_response(id, deadline)
        }

        fn read_response(&mut self, id: u64, deadline: Instant) -> io::Result<Value> {
            loop {
                let response = self.read_message(deadline).inspect_err(|error| {
                    if !matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) {
                        self.poisoned = true;
                    }
                })?;
                if self.record_event(&response)? {
                    self.pending_events += 1;
                    if self.pending_events > MAX_EVENTS_PER_RESPONSE {
                        self.poisoned = true;
                        return Err(invalid("QMP event rate exceeds the bounded owner response"));
                    }
                    continue;
                }
                if response["id"].as_u64() != Some(id) {
                    self.poisoned = true;
                    return Err(invalid("QMP response does not match its owner command"));
                }
                self.pending_response = None;
                self.pending_events = 0;
                if response.get("error").is_some() {
                    return Err(invalid("QMP owner operation was rejected"));
                }
                return response
                    .get("return")
                    .cloned()
                    .ok_or_else(|| invalid("QMP response has no result"));
            }
        }

        fn set_deadline(&self, deadline: Instant) -> io::Result<()> {
            let now = Instant::now();
            if deadline <= now {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.stream.get_ref().set_io_timeout(Some(deadline - now))
        }

        fn read_message(&mut self, deadline: Instant) -> io::Result<Value> {
            loop {
                self.set_deadline(deadline)?;
                let available = self.stream.fill_buf()?;
                if available.is_empty() {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                let end = available
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map(|position| position + 1);
                let count = end.unwrap_or(available.len());
                if self.partial_message.len() + count > MAX_MESSAGE {
                    return Err(invalid("QMP message exceeds native bound"));
                }
                self.partial_message.extend_from_slice(&available[..count]);
                self.stream.consume(count);
                if end.is_some() {
                    let message = serde_json::from_slice(&self.partial_message)
                        .map_err(|_| invalid("malformed QMP owner message"));
                    self.partial_message.clear();
                    return message;
                }
            }
        }
    }

    fn file_channel(path: &Path) -> io::Result<Value> {
        let text = path
            .to_str()
            .ok_or_else(|| invalid("native state path must be UTF-8"))?;
        if !path.is_absolute() || text.len() > 4096 || text.contains('\0') {
            return Err(invalid(
                "native state file must be an absolute bounded path",
            ));
        }
        Ok(json!({"channels": [{"channel-type": "main", "addr": {
            "transport": "file", "filename": text, "offset": 0
        }}]}))
    }

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::{TcpListener, TcpStream};

        #[test]
        fn full_capture_requires_transfer_completion_and_a_stopped_cpu_postcondition() {
            for final_state in ["postmigrate", "paused", "running"] {
                let (stream, peer) = pair();
                let worker = std::thread::spawn(move || {
                    let mut peer = BufReader::new(peer);
                    greeting(peer.get_mut());
                    for (id, operation, value) in [
                        (1, "qmp_capabilities", json!({})),
                        (
                            2,
                            "query-status",
                            json!({"status":"paused","running":false}),
                        ),
                        (3, "migrate", json!({})),
                        (4, "query-migrate", json!({"status":"completed"})),
                        (
                            5,
                            "query-status",
                            json!({"status":final_state,"running":final_state=="running"}),
                        ),
                    ] {
                        let request = command(&mut peer);
                        assert_eq!(request["execute"], operation);
                        if operation == "migrate" {
                            assert_eq!(
                                request["arguments"]["channels"][0]["addr"],
                                json!({"transport":"file","filename":"/owned/snapshot.vmstate","offset":0})
                            );
                            assert!(request["arguments"].get("uri").is_none());
                        }
                        writeln!(peer.get_mut(), "{}", json!({"return":value,"id":id})).unwrap();
                    }
                });
                let mut control = QemuControl::open(stream, Duration::from_secs(1)).unwrap();
                assert_eq!(
                    control
                        .save_state(Path::new("/owned/snapshot.vmstate"))
                        .is_ok(),
                    final_state != "running"
                );
                worker.join().unwrap();
            }
        }

        #[test]
        fn migration_failure_and_control_loss_cannot_become_saved_state() {
            for outcome in [Some("failed"), Some("cancelled"), Some("unknown"), None] {
                let (stream, peer) = pair();
                let worker = std::thread::spawn(move || {
                    let mut peer = BufReader::new(peer);
                    greeting(peer.get_mut());
                    for (id, value) in [
                        (1, json!({})),
                        (2, json!({"status":"paused","running":false})),
                        (3, json!({})),
                    ] {
                        command(&mut peer);
                        writeln!(peer.get_mut(), "{}", json!({"return":value,"id":id})).unwrap();
                    }
                    command(&mut peer);
                    if let Some(status) = outcome {
                        writeln!(
                            peer.get_mut(),
                            "{}",
                            json!({"return":{"status":status},"id":4})
                        )
                        .unwrap();
                    }
                });
                let mut control = QemuControl::open(stream, Duration::from_secs(1)).unwrap();
                assert!(
                    control
                        .save_state(Path::new("/owned/snapshot.vmstate"))
                        .is_err()
                );
                worker.join().unwrap();
            }
            assert!(file_channel(Path::new("relative.vmstate")).is_err());
            assert!(file_channel(Path::new("exec:arbitrary-program")).is_err());
        }

        #[test]
        fn partition_measurements_are_bounded_and_do_not_define_power() {
            for sample in [
                json!({"total-runtime-micros":123,"hypervisor-runtime-micros":7,"virtual-processors":2}),
                json!({"total-runtime-micros":123,"hypervisor-runtime-micros":7,"virtual-processors":0}),
                json!({"total-runtime-micros":123,"hypervisor-runtime-micros":7,"virtual-processors":33}),
                json!({"total-runtime-micros":123,"virtual-processors":2}),
                json!({"total-runtime-micros":u64::MAX,"hypervisor-runtime-micros":7,"virtual-processors":2}),
                json!({"total-runtime-micros":123,"hypervisor-runtime-micros":7,"virtual-processors":2,"guest-assertion":true}),
                Value::Null,
            ] {
                let valid = sample
                    == json!({"total-runtime-micros":123,"hypervisor-runtime-micros":7,"virtual-processors":2});
                let (stream, peer) = pair();
                let worker = std::thread::spawn(move || {
                    let mut peer = BufReader::new(peer);
                    greeting(peer.get_mut());
                    assert_eq!(command(&mut peer)["execute"], "qmp_capabilities");
                    writeln!(peer.get_mut(), "{}", json!({"return":{},"id":1})).unwrap();
                    let request = command(&mut peer);
                    assert_eq!(request["execute"], "query-sandsurf-partition-counters");
                    assert_eq!(request["arguments"], json!({}));
                    let response = if sample.is_null() {
                        json!({"error":{"class":"GenericError","desc":"partition measurement unavailable"},"id":2})
                    } else {
                        json!({"return":sample,"id":2})
                    };
                    writeln!(peer.get_mut(), "{response}").unwrap();
                    assert_eq!(command(&mut peer)["execute"], "query-status");
                    writeln!(
                        peer.get_mut(),
                        "{}",
                        json!({"return":{"status":"running","running":true},"id":3})
                    )
                    .unwrap();
                });
                let mut control = QemuControl::open(stream, Duration::from_secs(1)).unwrap();
                assert_eq!(control.partition_usage().is_ok(), valid);
                assert_eq!(control.status().unwrap(), "running");
                worker.join().unwrap();
            }
        }

        #[test]
        fn restore_cannot_resume_cpu_as_a_side_effect_of_loading_memory() {
            for final_state in ["paused", "running"] {
                let (stream, peer) = pair();
                let worker = std::thread::spawn(move || {
                    let mut peer = BufReader::new(peer);
                    greeting(peer.get_mut());
                    for (id, operation, value) in [
                        (1, "qmp_capabilities", json!({})),
                        (
                            2,
                            "query-status",
                            json!({"status":"inmigrate","running":false}),
                        ),
                        (3, "migrate-incoming", json!({})),
                        (4, "query-migrate", json!({"status":"completed"})),
                        (
                            5,
                            "query-status",
                            json!({"status":final_state,"running":final_state=="running"}),
                        ),
                    ] {
                        assert_eq!(command(&mut peer)["execute"], operation);
                        writeln!(peer.get_mut(), "{}", json!({"return":value,"id":id})).unwrap();
                    }
                });
                let mut control = QemuControl::open(stream, Duration::from_secs(1)).unwrap();
                assert_eq!(
                    control
                        .load_state(Path::new("/owned/snapshot.vmstate"))
                        .is_ok(),
                    final_state == "paused"
                );
                worker.join().unwrap();
            }
        }
        fn pair() -> (SocketConnection, TcpStream) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (socket, _) = listener.accept().unwrap();
            (
                SocketConnection::new(socket.into(), Some(Duration::from_secs(1))).unwrap(),
                peer,
            )
        }
        fn greeting(peer: &mut TcpStream) {
            peer.write_all(
                b"{\"QMP\":{\"version\":{\"qemu\":{\"major\":10}},\"capabilities\":[]}}\r\n",
            )
            .unwrap();
        }
        fn command(peer: &mut BufReader<TcpStream>) -> Value {
            let mut line = String::new();
            peer.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap()
        }
        #[test]
        fn final_native_reset_is_drained_without_writing_to_a_dead_owner() {
            let (stream, peer) = pair();
            let worker = std::thread::spawn(move || {
                let mut peer = BufReader::new(peer);
                greeting(peer.get_mut());
                command(&mut peer);
                peer.get_mut().write_all(b"{\"return\":{},\"id\":1}\n{\"event\":\"SHUTDOWN\",\"data\":{\"guest\":true,\"reason\":\"guest-reset\"}}\n").unwrap();
                // Close immediately. No query/response transaction is necessary.
            });
            let mut control = QemuControl::open(stream, Duration::from_secs(1)).unwrap();
            worker.join().unwrap();
            control.drain_exit_events().unwrap();
            assert!(control.take_power_events().guest_reset.is_some());
        }
        #[test]
        fn truncated_final_event_is_unavailable_not_a_guest_shutdown() {
            let (stream, peer) = pair();
            let worker = std::thread::spawn(move || {
                let mut peer = BufReader::new(peer);
                greeting(peer.get_mut());
                command(&mut peer);
                peer.get_mut()
                    .write_all(b"{\"return\":{},\"id\":1}\n{\"event\":\"SHUTDOWN\"")
                    .unwrap();
            });
            let mut control = QemuControl::open(stream, Duration::from_secs(1)).unwrap();
            worker.join().unwrap();
            assert!(control.drain_exit_events().is_err());
            assert!(control.take_power_events().shutdown.is_none());
        }
        #[test]
        fn native_reset_is_distinct_from_shutdown_and_guest_management() {
            let (stream, peer) = pair();
            let worker = std::thread::spawn(move || {
                let mut peer = BufReader::new(peer);
                greeting(peer.get_mut());
                assert_eq!(command(&mut peer)["execute"], "qmp_capabilities");
                peer.get_mut()
                    .write_all(b"{\"return\":{},\"id\":1}\n")
                    .unwrap();
                assert_eq!(command(&mut peer)["execute"], "query-status");
                peer.get_mut().write_all(b"{\"event\":\"SHUTDOWN\",\"data\":{\"guest\":true,\"reason\":\"guest-reset\"}}\n{\"return\":{\"status\":\"shutdown\",\"running\":false},\"id\":2}\n").unwrap();
            });
            let mut control = QemuControl::open(stream, Duration::from_secs(1)).unwrap();
            assert_eq!(control.status().unwrap(), "shutdown");
            assert!(control.take_power_events().guest_reset.is_some());
            assert!(control.take_power_events().guest_reset.is_none());
            worker.join().unwrap();
        }
        #[test]
        fn interrupted_observation_keeps_framing_but_never_publishes_late_power() {
            let (stream, peer) = pair();
            let (release, resumed) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let mut peer = BufReader::new(peer);
                greeting(peer.get_mut());
                command(&mut peer);
                peer.get_mut()
                    .write_all(b"{\"return\":{},\"id\":1}\n")
                    .unwrap();
                assert_eq!(command(&mut peer)["id"], 2);
                peer.get_mut()
                    .write_all(b"{\"return\":{\"status\":\"pau")
                    .unwrap();
                resumed.recv_timeout(Duration::from_secs(3)).unwrap();
                peer.get_mut()
                    .write_all(b"sed\",\"running\":false},\"id\":2}\n")
                    .unwrap();
                assert_eq!(command(&mut peer)["id"], 3);
                peer.get_mut()
                    .write_all(b"{\"return\":{\"status\":\"running\",\"running\":true},\"id\":3}\n")
                    .unwrap();
            });
            let mut control = QemuControl::open(stream, Duration::from_secs(1)).unwrap();
            control.timeout = Duration::from_millis(30);
            assert_eq!(
                control.status().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
            assert_eq!(control.pending_response, Some(2));
            assert!(!control.partial_message.is_empty());
            release.send(()).unwrap();
            control.timeout = Duration::from_secs(1);
            assert_eq!(control.status().unwrap(), "running");
            assert!(control.pending_response.is_none());
            worker.join().unwrap();
        }

        #[test]
        fn event_flood_budget_is_per_transaction_not_reset_by_observation_timeout() {
            let (stream, peer) = pair();
            let (release, resumed) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let mut peer = BufReader::new(peer);
                greeting(peer.get_mut());
                command(&mut peer);
                peer.get_mut()
                    .write_all(b"{\"return\":{},\"id\":1}\n")
                    .unwrap();
                command(&mut peer);
                for _ in 0..MAX_EVENTS_PER_RESPONSE {
                    peer.get_mut().write_all(b"{\"event\":\"STOP\"}\n").unwrap();
                }
                resumed.recv_timeout(Duration::from_secs(3)).unwrap();
                peer.get_mut().write_all(b"{\"event\":\"STOP\"}\n").unwrap();
            });
            let mut control = QemuControl::open(stream, Duration::from_secs(1)).unwrap();
            control.timeout = Duration::from_millis(100);
            assert_eq!(
                control.status().unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
            assert_eq!(control.pending_events, MAX_EVENTS_PER_RESPONSE);
            release.send(()).unwrap();
            control.timeout = Duration::from_secs(1);
            assert_eq!(
                control.status().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(control.poisoned);
            worker.join().unwrap();
        }
        #[test]
        fn mismatched_responses_and_unbounded_messages_cannot_be_power_evidence() {
            for payload in [
                b"{\"return\":{},\"id\":99}\n".to_vec(),
                vec![b' '; MAX_MESSAGE + 1],
            ] {
                let (stream, peer) = pair();
                let worker = std::thread::spawn(move || {
                    let mut peer = BufReader::new(peer);
                    greeting(peer.get_mut());
                    command(&mut peer);
                    let _ = peer.get_mut().write_all(&payload);
                });
                assert_eq!(
                    QemuControl::open(stream, Duration::from_secs(1))
                        .err()
                        .unwrap()
                        .kind(),
                    io::ErrorKind::InvalidData
                );
                worker.join().unwrap();
            }
        }
        #[test]
        fn disconnected_control_never_becomes_stopped_power() {
            let (stream, peer) = pair();
            drop(peer);
            assert_eq!(
                QemuControl::open(stream, Duration::from_secs(1))
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }
}
