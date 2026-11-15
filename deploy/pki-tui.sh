#!/bin/sh
# Purpose: host-only Python/curses PKI operator over the shared mTLS HTTP client.
# Usage: deploy/pki-tui.sh --url ORIGIN --realm ID --trust PEM --p12 P12 --checkpoint DIR
# Inputs: local credential references; password on terminal or inherited --password-fd.
# Outputs: interactive catalog/forms/retained requests; explicitly selected local artifacts.
# Exit: 0 normal UI exit; 2 setup failure. Request screens distinguish 0/2/3/4 outcomes.
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "${HERE}/pki_tui.py" "$@"
