#!/bin/sh
case "${0##*/}" in
    fake-trivy-flood)
        exec head -c 1048576 /dev/zero
        ;;
    fake-trivy-report)
        exec cat "$(dirname "$0")/report.json"
        ;;
    fake-trivy-hang)
        exec sleep 30
        ;;
    *)
        printf 'unknown fake Trivy mode: %s\n' "$0" >&2
        exit 2
        ;;
esac
