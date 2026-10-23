#!/usr/bin/env bash
# Boot a disposable KVM guest; never runs apply against the host.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CACHE="${VM_CACHE:-/var/tmp/php-safepatch-vm-cache}"
OUT="${VM_OUTPUT:-$REPO/tests/out/vm-rocky9-$(date -u +%Y%m%dT%H%M%SZ)}"
PORT=22229
for cmd in qemu-system-x86_64 qemu-img cloud-localds ssh ssh-keygen curl tar sha256sum; do
  command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 2; }
done
# QEMU opens /dev/kvm read-write.
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "/dev/kvm must be readable and writable" >&2; exit 2; }
# A guest that still runs (VM_KEEP_RUNNING=1) or a port that is not released yet would make
# this run talk to another machine or fail later; stop now with a clear message.
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  echo "Port 127.0.0.1:$PORT is in use. Stop the old guest (or wait a few seconds) and run again." >&2
  exit 2
fi
mkdir -p "$CACHE" "$OUT"
# Host-side hashes of everything that goes into the guest, and of this runner.
(cd "$REPO" && sha256sum tests/vm/run-rocky9.sh tests/vm/rocky9-cases.sh tests/lib/assert.sh \
  linux/php-safepatch.sh advisories/php2shell.conf) >"$OUT/host-sha256.txt"

IMAGE="$CACHE/Rocky-9.qcow2"
NAME=Rocky-9-GenericCloud-Base.latest.x86_64.qcow2
BASE=https://download.rockylinux.org/pub/rocky/9/images/x86_64
curl -fsSL "$BASE/CHECKSUM" -o "$OUT/CHECKSUM"
expected="$(sed -n "s/^SHA256 ($NAME) = //p" "$OUT/CHECKSUM")"
[ -n "$expected" ] || { echo "No checksum for $NAME in $BASE/CHECKSUM" >&2; exit 2; }
image_ok() { [ -s "$IMAGE" ] && printf '%s  %s\n' "$expected" "$IMAGE" | sha256sum -c --status -; }
# "latest" changes when Rocky publishes a new image. A cached image with an old checksum is
# downloaded again once; a second mismatch is an error.
if ! image_ok; then
  [ -s "$IMAGE" ] && echo "Cached image does not match the current checksum; downloading again." >&2
  curl -fL --retry 2 "$BASE/$NAME" -o "$IMAGE.part"
  mv "$IMAGE.part" "$IMAGE"
fi
printf '%s  %s\n' "$expected" "$IMAGE" | sha256sum -c - | tee "$OUT/image-checksum.txt"
printf 'image: %s\nsha256: %s\nsource: %s/%s\n' "$IMAGE" "$expected" "$BASE" "$NAME" >"$OUT/image.txt"

RUN="$(mktemp -d /var/tmp/php-safepatch-kvm.XXXXXX)"
printf '%s\n' "$RUN" >"$OUT/guest-workdir.txt"
cleanup() {
  if [ "${VM_KEEP_RUNNING:-0}" = 1 ]; then
    printf 'Guest retained for debugging: %s (SSH key and overlay are there)\n' "$RUN"
    return
  fi
  if [ -f "$RUN/qemu.pid" ]; then
    local pid; pid="$(cat "$RUN/qemu.pid")"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  fi
  # The overlay and the private SSH key are only for this guest.
  if [ "${VM_KEEP_FILES:-0}" = 1 ]; then
    printf 'Guest files retained: %s\n' "$RUN"
  else
    rm -rf -- "$RUN"
  fi
}
trap cleanup EXIT
ssh-keygen -q -t ed25519 -N '' -f "$RUN/key"
cat >"$RUN/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys:
      - $(cat "$RUN/key.pub")
runcmd:
  - [touch, /run/phpdoctor-disposable-vm]
EOF
printf 'instance-id: phpdoctor-%s\nlocal-hostname: phpdoctor-vm\n' "$(date +%s)" >"$RUN/meta-data"
cloud-localds "$RUN/seed.img" "$RUN/user-data" "$RUN/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$IMAGE" "$RUN/disk.qcow2" 16G
qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 2048 \
  -drive "file=$RUN/disk.qcow2,format=qcow2,if=virtio" \
  -drive "file=$RUN/seed.img,format=raw,if=virtio,readonly=on" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$PORT-:22" \
  -device virtio-net-pci,netdev=net0 -display none \
  -serial "file:$OUT/serial.log" -monitor none -daemonize -pidfile "$RUN/qemu.pid"
SSH=(ssh -p "$PORT" -i "$RUN/key" -o BatchMode=yes -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$RUN/known_hosts" -o ConnectTimeout=5 root@127.0.0.1)
ready=0
for ((n=0; n<90; n++)); do
  if "${SSH[@]}" true 2>/dev/null; then ready=1; break; fi
  sleep 2
done
test "$ready" = 1
"${SSH[@]}" 'cloud-init status --wait; mkdir -p /root/phpdoctor /root/vm-results'
tar -C "$REPO" -cf - linux advisories tests/lib/assert.sh tests/vm/rocky9-cases.sh \
  | "${SSH[@]}" 'tar -C /root/phpdoctor -xf -'
set +e
"${SSH[@]}" 'bash /root/phpdoctor/tests/vm/rocky9-cases.sh' 2>&1 | tee "$OUT/test.log"
rc=${PIPESTATUS[0]}
"${SSH[@]}" 'tar -C /root/vm-results -cf - .' | tar -C "$OUT" -xf -
set -e
printf '\nVM exit: %s\nEvidence: %s\n' "$rc" "$OUT"
exit "$rc"
