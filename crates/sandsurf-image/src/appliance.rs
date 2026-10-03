//! One offline filesystem session in a reviewed, NIC-less hardware VM. The
//! host owns opened transfer files and native custody; guest RPCs never carry
//! host paths. No package program or disk filesystem enters the host kernel.
use sandsurf_machine::offline::{Config, OfflineVm};
use sandsurf_native::GuestConnection;
use sandsurf_protocol::disk::{
    DiskChannel, DiskCompression, DiskOperation, DiskReply, MAX_DISK_OPERATIONS,
};
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;

/// The host supplies only its reviewed runtime and original input leases. An
/// arbitrary machine's mutable boot image is never an offline executor TCB.
pub trait Executor {
    fn identity(&mut self) -> io::Result<String>;
    fn open(
        &mut self,
        disk: &Path,
        writable: bool,
        custody: Vec<Arc<File>>,
    ) -> io::Result<Appliance>;
}

/// Boot inspection also serves the independent build-time TCB producer. It
/// shares validation, not a fallback backend in the installed product.
pub trait Filesystem {
    fn run(&mut self, operation: DiskOperation) -> io::Result<DiskReply>;
    fn download(&mut self, guest: &str, output: &Path, maximum: u64) -> io::Result<()>;
}

pub struct Appliance {
    owner: OfflineVm,
    channel: DiskChannel<Box<dyn GuestConnection>>,
    writable: bool,
    operations: u64,
    failed: bool,
}

impl Appliance {
    pub fn launch(config: Config) -> io::Result<Self> {
        let writable = config.writable;
        let mut owner = OfflineVm::launch(config)?;
        let channel = DiskChannel::new(owner.connect()?);
        Ok(Self {
            owner,
            channel,
            writable,
            operations: 0,
            failed: false,
        })
    }

    fn request(&mut self, operation: &DiskOperation) -> io::Result<()> {
        if self.failed || self.operations >= MAX_DISK_OPERATIONS {
            return Err(invalid(
                "offline session failed or operation budget exhausted",
            ));
        }
        operation.validate(self.writable)?;
        self.operations += 1;
        // Any ambiguous partial effect ends the session. No reconnect/replay.
        self.failed = true;
        self.channel.send_metadata(operation)
    }

    fn reply(&mut self, operation: &DiskOperation) -> io::Result<DiskReply> {
        let reply: DiskReply = self.channel.metadata()?;
        reply.validate_for(operation)?;
        if let DiskReply::Failed { message } = reply {
            return Err(io::Error::other(message));
        }
        self.failed = false;
        Ok(reply)
    }

    pub fn import_tar(&mut self, input: &Path, compression: DiskCompression) -> io::Result<()> {
        let mut input = sandsurf_native::local::open_private_file(
            input,
            sandsurf_native::PrivateFileAccess::ReadOnly,
        )?;
        let bytes = input.metadata()?.len();
        let operation = DiskOperation::ImportTar { bytes, compression };
        self.request(&operation)?;
        self.channel.send_data(&mut input, bytes)?;
        if input.metadata()?.len() != bytes {
            return Err(invalid("archive changed during transfer"));
        }
        self.reply(&operation)?;
        Ok(())
    }

    /// This is a publication barrier, not a guest receipt acknowledgement.
    /// Even an error session is terminated through its original native owner.
    pub fn finish(self) -> io::Result<()> {
        let failed = self.failed;
        self.owner.finish()?;
        if failed {
            return Err(invalid("offline session has an incomplete operation"));
        }
        Ok(())
    }
}

impl Filesystem for Appliance {
    fn run(&mut self, operation: DiskOperation) -> io::Result<DiskReply> {
        if matches!(
            operation,
            DiskOperation::ImportTar { .. } | DiskOperation::Download { .. }
        ) {
            return Err(invalid("bulk operation requires an opened host transfer"));
        }
        self.request(&operation)?;
        self.reply(&operation)
    }

    fn download(&mut self, guest: &str, output: &Path, maximum: u64) -> io::Result<()> {
        let bytes = self
            .run(DiskOperation::FileSize { path: guest.into() })?
            .size()?;
        if bytes == 0 || bytes > maximum {
            return Err(invalid("selected guest artifact exceeds its bound"));
        }
        let mut output = sandsurf_native::local::create_private_file(output)?;
        let operation = DiskOperation::Download {
            path: guest.into(),
            offset: 0,
            bytes,
        };
        self.request(&operation)?;
        self.reply(&operation)?;
        self.failed = true;
        self.channel.data(&mut output, bytes)?;
        sandsurf_native::storage::sync_file(&output)?;
        if output.metadata()?.len() != bytes {
            return Err(invalid("incomplete guest artifact capture"));
        }
        self.failed = false;
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
