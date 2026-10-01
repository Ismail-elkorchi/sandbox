#!/bin/sh
set -eu
# All paths and programs here are inside the disposable build VM. The package
# archive carries signed APKs and a complete, separately digest-pinned lock.
apk --no-network --cache-dir /var/cache/apk --repositories-file /dev/null add /var/cache/apk/*.apk
apk info -e alpine-base ca-certificates busybox-extras git openrc sudo e2fsprogs e2fsprogs-extra openssh linux-virt mkinitfs >/dev/null
awk '/^P:/ {name=substr($0,3)} /^V:/ {print name "=" substr($0,3)}' /lib/apk/db/installed | LC_ALL=C sort > /actual-package-lock
cmp /actual-package-lock /expected-package-lock
addgroup -g 1000 agent
adduser -D -u 1000 -G agent -h /home/agent agent
mkdir -p /workspace /home/agent /var/lib/sandsurf /etc/runlevels/default /etc/runlevels/boot /etc/runlevels/sysinit /etc/runlevels/shutdown
chown 1000:1000 /workspace /home/agent
chmod 4755 /usr/bin/sudo
mkdir -p /etc/conf.d
printf 'rc_need="sandsurf-clone-identity"\n' >> /etc/conf.d/sshd
printf 'rc_cgroup_mode="unified"\n' > /etc/rc.conf
for service in devfs procfs sysfs mdev cgroups; do ln -sf ../../init.d/$service /etc/runlevels/sysinit/$service; done
for service in root sandsurf-expand-root localmount bootmisc machine-id hostname loopback networking; do ln -sf ../../init.d/$service /etc/runlevels/boot/$service; done
for service in sandsurf-clone-identity sandsurf-management sshd; do ln -sf ../../init.d/$service /etc/runlevels/default/$service; done
for service in killprocs mount-ro; do ln -sf ../../init.d/$service /etc/runlevels/shutdown/$service; done
# virtio storage/MMIO/PCI, ext4 and vsock are needed across direct-boot adapters.
printf 'features="base ext4 virtio"\n' > /etc/mkinitfs/mkinitfs.conf
set -- /lib/modules/*-virt
[ "$#" = 1 ] && [ -f "$1/modules.order" ]
mkinitfs -o /boot/initramfs-virt "${1##*/}"
# APK's earlier kernel hook selected a different initial initramfs. This is a
# new build disk: discard only that generated selection store and publish the
# final pair, rather than shipping unreachable historical boot payloads.
rm -rf /boot/sandsurf
/usr/sbin/sandsurf-select-boot
rm -f /etc/machine-id /var/lib/dbus/machine-id /etc/ssh/ssh_host_* /var/lib/urandom/random-seed
rm -f /actual-package-lock /expected-package-lock /sandsurf-build.sh
# These are build inputs, not an agent-created package cache. Installed
# software and APK's installed database remain; do not ship the signed input
# archives twice or retain build-only bytes in a published machine seed.
rm -f /var/cache/apk/*.apk
sync
