#!/bin/sh
# Purpose: reusable host-only PKI operator requests and binary artifacts over mTLS.
# Usage: deploy/pki-operator.sh --url ORIGIN --realm ID --trust PEM --p12 P12 --checkpoint DIR COMMAND
# Inputs: private structured JSON/local credentials; password on TTY or inherited FD.
# Outputs: JSON result on stdout; new private artifact files and durable checkpoints.
# Exit: 0 completed; 2 invalid/failed; 3 pending/approval; 4 unknown acceptance.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "${HERE}/pki_operator.py" "$@"
