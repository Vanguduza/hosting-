#!/usr/bin/env bash
# Pinned CI fixture dependency; avoid an unbounded Ubuntu mirror update.
set -Eeuo pipefail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]
restic_ci_target="${1:?Specify an absolute installation directory}"
[[ "$restic_ci_target" == /* && ! -L "$restic_ci_target" ]]
mkdir -p -- "$restic_ci_target"
restic_ci_scratch="$(mktemp -d -t hosting-restic-ci.XXXXXXXX)"
cleanup() {
  rm -f -- "$restic_ci_scratch/restic.bz2" "$restic_ci_scratch/restic"
  rmdir -- "$restic_ci_scratch"
}
trap cleanup EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 10 --max-time 60 --retry 2 --retry-delay 2 --retry-max-time 180 \
  https://github.com/restic/restic/releases/download/v0.18.1/restic_0.18.1_linux_amd64.bz2 \
  -o "$restic_ci_scratch/restic.bz2"
printf '%s  %s\n' '680838f19d67151adba227e1570cdd8af12c19cf1735783ed1ba928bc41f363d' \
  "$restic_ci_scratch/restic.bz2" | sha256sum --check --status
bzip2 -dc "$restic_ci_scratch/restic.bz2" > "$restic_ci_scratch/restic"
install -m 755 "$restic_ci_scratch/restic" "$restic_ci_target/restic"
"$restic_ci_target/restic" version
