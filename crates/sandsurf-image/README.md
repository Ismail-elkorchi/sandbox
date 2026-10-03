Runtime filesystem construction, boot extraction and identity editing use one
disposable, NIC-less hardware VM per disk session. Linux uses the same original
Firecracker owner as computers; macOS and Windows use owned HVF/WHPX QEMU.
The executor boots the exact image manifest pinned into the installed native
host, with a read-only root and an explicitly attached raw target disk. It never
boots the target's kernel or init. The bounded disk protocol transfers bytes,
not host filenames, credentials, mounts or network capabilities. Filesystems
are mounted only inside the VM; distribution programs run in its target-root
mount namespace. Returned metadata is bounded guest information, not host
attestation. Original pool, publication and input leases reach the actual VMM;
publication waits for confirmed native termination. There is no libguestfs
runtime path, software emulation or host filesystem-execution fallback.

`scripts/build-guest-image.ts` is the independent bootstrap producer for that
reviewed execution image and requires a same-architecture Linux/KVM host. Its
build-only libguestfs producer is not linked into installed host execution. It
uses protected root-owned tools, a network-disabled 512MiB KVM appliance and a
300-second process-group deadline. Its input preparer verifies a signed APK
closure inside the isolated appliance.
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

Managed disk extraction and customization require the installed reviewed boot
image, native hardware runtime, bounded storage and original native ownership.
Missing prerequisites fail explicitly. Source builds and parser tests do not
qualify VM execution or create signed release artifacts. Installed computer
tests cover journaled roots, fork identity and persistence on eligible hosts.
