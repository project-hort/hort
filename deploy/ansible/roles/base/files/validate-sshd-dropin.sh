#!/bin/sh
# validate-sshd-dropin.sh — Ansible validate helper for sshd drop-in config.
#
# Usage (set as ansible.builtin.template validate):
#   validate: /bin/sh /path/to/validate-sshd-dropin.sh %s
#
# Ansible passes the temp file path as $1.  This script copies the file to a
# temp name inside sshd_config.d, runs `sshd -t` (which reads the full config
# including all drop-ins), then removes the temp file.  This correctly validates
# the drop-in in context of the full sshd config, including host key resolution.
#
# Requires: sshd installed on the target (the base role installs openssh-server
# as part of the same play via the dependency on the ssh package being present).

set -eu

DROPIN_PATH="$1"
TEMP_DROPIN="/etc/ssh/sshd_config.d/.10-hort-hardening.conf.validate-tmp"

cleanup() {
    rm -f "${TEMP_DROPIN}"
}
trap cleanup EXIT

cp "${DROPIN_PATH}" "${TEMP_DROPIN}"
chmod 0600 "${TEMP_DROPIN}"
sshd -t
