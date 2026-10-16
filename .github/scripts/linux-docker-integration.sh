#!/usr/bin/env bash
# Run the opt-in Linux Docker integration tests on a disposable CI runner, with
# the inputs the control-plane README documents. The runner is the trusted
# controller for this one run; it never prints the secrets the README blocks
# generate. Failures are also reported as annotations, which anyone can read
# without the run's logs.
set -euo pipefail

stage="setup"
trap 'echo "::error title=linux-docker::failed during ${stage}"' ERR

# The reviewed seccomp policy: Docker's default profile at a pinned commit.
POLICY_URL="https://raw.githubusercontent.com/moby/profiles/61eaf32614c7c71b60bd8927d3e6a4ffc8ff1f31/seccomp/default.json"
POLICY_SHA256="536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74"

root="$(cd "$(dirname "$0")/../.." && pwd)"
control_plane="$root/services/control-plane"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

stage="seccomp policy"
policies="$HOME/.local/share/failroom/policies"
install -d -m 0700 "$policies"
curl -fsSL --retry 3 "$POLICY_URL" -o "$policies/reviewed-default.json"
echo "$POLICY_SHA256  $policies/reviewed-default.json" | sha256sum --check --quiet

# The I/O limit applies to the whole disk that holds Docker's data root.
stage="I/O device"
majmin="$(findmnt -n -o MAJ:MIN --target "$(docker info --format '{{.DockerRootDir}}')" | tr -d '[:space:]')"
disk="$(readlink -f "/sys/dev/block/$majmin")"
if [ -e "$disk/partition" ]; then
  disk="$(dirname "$disk")"
fi
io_device="/dev/$(basename "$disk")"
test -b "$io_device"
echo "::notice title=linux-docker::I/O device $io_device for $majmin"

# The README's environment blocks, with this runner's I/O device; the seccomp
# policy is already where the README expects it.
stage="README inputs"
awk '/^## Linux integration evidence/ { s = 1 }
  s && /^```sh/ { b = 1; buf = ""; next }
  s && b && /^```/ {
    b = 0
    if (buf ~ /export /) { f = sprintf("%s/block%d.sh", dir, ++k); printf "%s", buf > f; close(f) }
    next
  }
  s && b { buf = buf $0 "\n" }' dir="$work" "$control_plane/README.md"
sed -i "s#^export FAILROOM_IO_DEVICE=.*#export FAILROOM_IO_DEVICE=$io_device#" "$work/block1.sh"
cd "$control_plane"
for block in "$work"/block*.sh; do
  # shellcheck source=/dev/null
  . "$block"
done
export FAILROOM_DOCKER_INTEGRATION=1 FAILROOM_TERMINAL_INTEGRATION=1 FAILROOM_LOCAL_RUNTIME_INTEGRATION=1

# Run one suite, keeping its output, and annotate each failing test.
run_suite() {
  local directory="$1" pattern="$2" log="$work/suite.log" status=0
  (cd "$directory" && uv run --locked python -m unittest discover -s tests -p "$pattern" -v) 2>&1 \
    | tee "$log" || status=$?
  if [ "$status" -ne 0 ]; then
    { grep -E '^(FAIL|ERROR): ' "$log" || true; } | head -20 | while read -r line; do
      echo "::error title=linux-docker::$line"
    done
  fi
  return "$status"
}

stage="sandbox-engine integration tests"
run_suite ../sandbox-engine 'test_docker_diagnostic_integration.py'
stage="control-plane integration tests"
run_suite . 'test_linux_*.py'

# Nothing the tests created may outlive them.
stage="leftover check"
leftovers="$(docker ps -a --quiet --filter label=failroom.kind)"
if [ -n "$leftovers" ]; then
  echo "::error title=linux-docker::Failroom containers outlived the tests"
  docker ps -a --filter label=failroom.kind
  exit 1
fi

# Sandboxes are auto-remove containers. Docker removes one it finds stopped
# when its daemon starts again, which covers a deadline that passes while the
# daemon is down. Restart it last, with one such container running.
stage="daemon restart"
if [ "$(docker info --format '{{.LiveRestoreEnabled}}')" != "false" ]; then
  echo "::error title=linux-docker::live-restore keeps containers running across a daemon restart"
  exit 1
fi
sandbox="$(docker container create --rm --restart no --init --pull never \
  --label failroom.ci=daemon-restart --entrypoint /bin/sleep "$FAILROOM_DOCKER_IMAGE" 600)"
docker container start "$sandbox" >/dev/null
sudo systemctl restart docker
for _ in $(seq 1 60); do
  docker info >/dev/null 2>&1 && break
  sleep 1
done
for _ in $(seq 1 30); do
  docker container inspect "$sandbox" >/dev/null 2>&1 || break
  sleep 1
done
if docker container inspect "$sandbox" >/dev/null 2>&1; then
  echo "::error title=linux-docker::an auto-remove container outlived a Docker daemon restart"
  docker container rm --force "$sandbox" >/dev/null
  exit 1
fi
echo "::notice title=linux-docker::Docker removed an auto-remove container across a daemon restart"
