Image construction and mutable disk interpretation use a disposable Linux
libguestfs/QEMU appliance. Package programs, filesystem mounting, tar import,
fsck and identity editing run inside that VM. Host QEMU receives explicitly raw
disks, never autodetected guest container formats. No host chroot, guest ELF
loader, filesystem mount, debugfs, or package lifecycle script is permitted.
The root-owned guestfish, QEMU, timeout, system libraries and libguestfs appliance
are trusted prerequisites. The executor clears environment overrides, forces
the direct KVM backend, disables networking/shared directories, uses one 512 MiB
appliance, caps stdout to 16 KiB and kills its process group after 300 seconds.
See [libguestfs command isolation](https://libguestfs.org/guestfs.3.html#running-commands).

`scripts/build-guest-image.ts` requires a same-architecture Linux/KVM host. Its
input preparer verifies a signed APK closure inside the isolated appliance.
Reviewed inputs can instead supply an offline gzip tar of signed APKs under `var/cache/apk/`, and a complete installed
package lock (one `name=version` line per package, sorted). Supply absolute paths
with `SANDSURF_ALPINE_PACKAGES_ARCHIVE` and `SANDSURF_ALPINE_PACKAGE_LOCK`, and
their separately reviewed lowercase SHA-256 digests using the corresponding
`_SHA256` variables. The closure must include linux-virt, mkinitfs, openssh and
the packages requested by `scripts/guest-image/sandsurf-build.sh`. The appliance
checks signatures, runs ordinary lifecycle scripts offline, and compares the
installed closure against the supplied lock. There is no unsafe host fallback
if the appliance is missing. Builds declare Alpine boot and clone profiles.

Alpine supports one linux-virt kernel/module tree. The apk commit hook invalidates
`/boot/sandsurf.json` before changes, regenerates the matching initramfs after
commit, and publishes selection atomically. Interrupted or failed updates leave
an invalid selection and fail the next cold boot. Guest root can repair the
selection and run `sandsurf-select-boot` deliberately. This is guest OS policy,
not guest integrity attestation. Custom images declare a pinned boot contract;
an OCI recipe pins its explicitly selected boot image and must supply a bootable
OS init itself. OCI conversion does not install distribution integrations.

Cold boot holds storage custody while copying bounded selected files under
`/boot`; links must resolve under `/boot`. Each boot receives independent,
read-only host artifacts. Disk snapshots extract their next cold-boot selection
from the immutable captured disk. Full-state snapshots copy the native owner's
actual running artifacts; resume never reads the guest's next-boot selection.
Both bind boot artifact digests into their manifest identity. Derived images
use the captured boot artifacts, including guest kernel updates. No corrupt
selection silently loads the original kernel. Kernel format/architecture checks
do not qualify all kernel drivers or application workloads on real hardware.

The managed Alpine cloning contract replaces `/etc/machine-id`, removes the
documented OpenSSH rsa/ecdsa/ed25519/dsa host key paths and OS random seed paths,
and marks first boot to generate new SSH host keys before sshd/management.
Customization happens in a nonattachable stage; a host receipt binds the source
digest, contract and resulting disk digest before publication. Creation also
uses this contract. Application IDs, alternate SSH HostKey paths, user keys,
tokens and retained data remain copied and sensitive. A custom image must
explicitly choose `cloneProfile: {kind: "preserve"}` to accept identity cloning;
there is no universal sanitization claim. Full memory fork remains unsupported.

Managed disk extraction and customization currently require the Linux appliance.
macOS and Windows must provide a native isolated helper before these managed
profiles can run there. They fail explicitly; Windows also rejects initramfs
because its current direct boot contract lacks that input. Source-built images
are not hardware qualification or signed release artifacts. Packaged guest
binaries and release signatures must be rebuilt through the isolated recipe.
