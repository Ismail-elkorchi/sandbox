//! Bounded framing for QEMU's native `stream` Ethernet backend. The owner
//! supplies an already established private endpoint. This module neither
//! authenticates endpoints nor listens on a public/guest-reachable socket.
use crate::MAX_FRAME;
use socket2::Socket;
use std::io::{self, Read};

pub struct PacketStream {
    socket: Socket,
    input: [u8; MAX_FRAME + 4],
    received: usize,
    length: Option<usize>,
    output: Vec<u8>,
    written: usize,
}

impl PacketStream {
    pub fn new(socket: Socket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        socket.set_recv_buffer_size(32 * 1024)?;
        socket.set_send_buffer_size(32 * 1024)?;
        if socket.recv_buffer_size()? > 64 * 1024 || socket.send_buffer_size()? > 64 * 1024 {
            return Err(io::Error::other("native NIC stream buffers exceed bound"));
        }
        Ok(Self {
            socket,
            input: [0; MAX_FRAME + 4],
            received: 0,
            length: None,
            output: Vec::new(),
            written: 0,
        })
    }

    pub(crate) fn nonblocking(&self) -> io::Result<()> {
        self.socket.set_nonblocking(true)
    }

    pub fn receive(&mut self) -> io::Result<Vec<u8>> {
        self.flush_pending()?;
        loop {
            let end = self.length.map_or(4, |length| length + 4);
            match self.socket.read(&mut self.input[self.received..end]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "native NIC stream closed",
                    ));
                }
                Ok(count) => self.received += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
            if self.received == 4 && self.length.is_none() {
                let length =
                    u32::from_be_bytes(self.input[..4].try_into().expect("fixed header")) as usize;
                if !(14..=MAX_FRAME).contains(&length) {
                    // Contain the attachment rather than allocate/discard an
                    // attacker-selected payload or lose framing alignment.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "native NIC frame length exceeds Ethernet bounds",
                    ));
                }
                self.length = Some(length);
            }
            if self
                .length
                .is_some_and(|length| self.received == length + 4)
            {
                let frame = self.input[4..self.received].to_vec();
                self.received = 0;
                self.length = None;
                return Ok(frame);
            }
        }
    }

    pub fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        if !(14..=MAX_FRAME).contains(&frame.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native NIC output frame exceeds bound",
            ));
        }
        self.flush_pending()?;
        if !self.output.is_empty() {
            // At most one partial frame is retained. The gateway may drop the
            // next datagram; TCP retransmission remains the guest's concern.
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.output
            .extend_from_slice(&(frame.len() as u32).to_be_bytes());
        self.output.extend_from_slice(frame);
        self.flush_pending()
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        while self.written < self.output.len() {
            #[cfg(unix)]
            let flags = libc::MSG_NOSIGNAL;
            #[cfg(windows)]
            let flags = 0;
            match self
                .socket
                .send_with_flags(&self.output[self.written..], flags)
            {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => self.written += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        self.output.clear();
        self.written = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};

    fn pair() -> (PacketStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (owner, _) = listener.accept().unwrap();
        (PacketStream::new(owner.into()).unwrap(), peer)
    }

    #[test]
    fn partial_header_and_payload_keep_exact_boundaries() {
        let (mut stream, mut peer) = pair();
        peer.write_all(&[0, 0]).unwrap();
        assert_eq!(
            stream.receive().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        peer.write_all(&[0, 14, 1, 2, 3]).unwrap();
        assert_eq!(
            stream.receive().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        peer.write_all(&[4; 11]).unwrap();
        let mut expected = vec![1, 2, 3];
        expected.extend_from_slice(&[4; 11]);
        assert_eq!(stream.receive().unwrap(), expected);
        stream.send(&[5; 14]).unwrap();
        let mut bytes = [0; 18];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes[..4], &14u32.to_be_bytes());
        assert_eq!(&bytes[4..], &[5; 14]);
    }

    #[test]
    fn oversized_and_zero_length_frames_are_rejected_before_payload_reads() {
        for size in [0, 13, MAX_FRAME as u32 + 1, u32::MAX] {
            let (mut stream, mut peer) = pair();
            peer.write_all(&size.to_be_bytes()).unwrap();
            assert_eq!(
                stream.receive().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn closed_partial_frame_is_not_a_complete_packet() {
        let (mut stream, mut peer) = pair();
        peer.write_all(&14u32.to_be_bytes()).unwrap();
        peer.write_all(&[1; 7]).unwrap();
        drop(peer);
        assert_eq!(
            stream.receive().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
