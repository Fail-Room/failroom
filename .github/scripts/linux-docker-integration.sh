#!/usr/bin/env bash
# Run the opt-in Linux Docker integration tests on a disposable CI runner, with
# the inputs the control-plane README documents. The runner is the trusted
# controller for this one run; it never prints the secrets the README blocks
# generate.
set -euo pipefail

# The reviewed seccomp policy: Docker's default profile at a pinned commit.
POLICY_URL="https://raw.githubusercontent.com/moby/profiles/61eaf32614c7c71b60bd8927d3e6a4ffc8ff1f31/seccomp/default.json"
POLICY_SHA256="536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74"

root="$(cd "$(dirname "$0")/../.." && pwd)"
control_plane="$root/services/control-plane"
blocks="$(mktemp -d)"
trap 'rm -rf "$blocks"' EXIT

policies="$HOME/.local/share/failroom/policies"
install -d -m 0700 "$policies"
curl -fsSL --retry 3 "$POLICY_URL" -o "$policies/reviewed-default.json"
echo "$POLICY_SHA256  $policies/reviewed-default.json" | sha256sum --check --quiet

# The I/O limit applies to the whole disk that holds Docker's data root.
majmin="$(findmnt -n -o MAJ:MIN --target "$(docker info --format '{{.DockerRootDir}}')")"
disk="$(readlink -f "/sys/dev/block/$majmin")"
if [ -e "$disk/partition" ]; then
  disk="$(dirname "$disk")"
fi
io_device="/dev/$(basename "$disk")"
test -b "$io_device"

# The README's environment blocks, with this runner's I/O device; the seccomp
# policy is already where the README expects it.
awk '/^## Linux integration evidence/ { s = 1 }
  s && /^```sh/ { b = 1; buf = ""; next }
  s && b && /^```/ {
    b = 0
    if (buf ~ /export /) { f = sprintf("%s/block%d.sh", dir, ++k); printf "%s", buf > f; close(f) }
    next
  }
  s && b { buf = buf $0 "\n" }' dir="$blocks" "$control_plane/README.md"
sed -i "s#^export FAILROOM_IO_DEVICE=.*#export FAILROOM_IO_DEVICE=$io_device#" "$blocks/block1.sh"
cd "$control_plane"
for block in "$blocks"/block*.sh; do
  # shellcheck source=/dev/null
  . "$block"
done
export FAILROOM_DOCKER_INTEGRATION=1 FAILROOM_TERMINAL_INTEGRATION=1 FAILROOM_LOCAL_RUNTIME_INTEGRATION=1

(cd ../sandbox-engine && uv run --locked python -m unittest discover -s tests -p 'test_docker_diagnostic_integration.py' -v)
uv run --locked python -m unittest discover -s tests -p 'test_linux_*.py' -v

# Nothing the tests created may outlive them.
leftovers="$(docker ps -a --quiet --filter label=failroom.kind)"
if [ -n "$leftovers" ]; then
  echo "LEFTOVER_CONTAINERS" >&2
  docker ps -a --filter label=failroom.kind >&2
  exit 1
fi
