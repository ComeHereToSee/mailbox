#!/usr/bin/env bash
DIR="${MAILBOX_TEST_ENV:-/tmp/mailbox-test-env}"
doveadm -c "$DIR/dovecot.conf" stop 2>/dev/null || pkill -f "dovecot -c $DIR/dovecot.conf" || true
[ -f "$DIR/greenmail.pid" ] && kill "$(cat "$DIR/greenmail.pid")" 2>/dev/null; rm -f "$DIR/greenmail.pid"
