use sandsurf_native::local::LocalConnection;
use sandsurf_protocol::{Frame, FrameChannel};
use std::{io, time::Duration};

pub(crate) struct LocalFrameChannel<'a> {
    pub connection: &'a mut LocalConnection,
    pub timeout: Duration,
}
impl FrameChannel for LocalFrameChannel<'_> {
    fn send(&mut self, frame: Frame) -> io::Result<()> {
        self.connection.write_frame(&frame, self.timeout)
    }
    fn receive(&mut self) -> io::Result<Option<Frame>> {
        self.connection.read_frame(self.timeout)
    }
}
