#!/usr/bin/env bash
# Starts throwaway mail servers for the integration tests:
#   Dovecot  IMAP 11143 (STARTTLS) / 11993 (TLS), POP3 11110 / 11995, ManageSieve 14190
#   GreenMail SMTP 3025 / SMTPS 3465 (+ its own IMAP 3143 to inspect sent mail)
# Users: alice@test.local / bob@test.local, password "secret".
set -euo pipefail
DIR="${MAILBOX_TEST_ENV:-/tmp/mailbox-test-env}"
GREENMAIL_JAR="${GREENMAIL_JAR:-$DIR/greenmail.jar}"
mkdir -p "$DIR"/{run,state,mail,home}

# Dovecot refuses uid 0 for mail access; use a dedicated user when running as root.
if [ "$(id -u)" = "0" ]; then
  id vmail >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin vmail
  MAIL_UID=$(id -u vmail); MAIL_GID=$(id -g vmail)
  chown -R vmail:vmail "$DIR/mail" "$DIR/home"
  EXTRA=""
else
  MAIL_UID=$(id -u); MAIL_GID=$(id -g)
  EXTRA="default_internal_user = $(id -un)
default_login_user = $(id -un)"
fi

if [ ! -f "$DIR/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
    -days 365 -subj "/CN=localhost" >/dev/null 2>&1
fi

cat > "$DIR/users" <<USERS
alice@test.local:{PLAIN}secret
bob@test.local:{PLAIN}secret
USERS

cat > "$DIR/dovecot.conf" <<CONF
base_dir = $DIR/run
state_dir = $DIR/state
log_path = $DIR/dovecot.log
protocols = imap pop3 sieve
listen = 127.0.0.1
ssl = yes
ssl_cert = <$DIR/cert.pem
ssl_key = <$DIR/key.pem
disable_plaintext_auth = no
auth_mechanisms = plain login
first_valid_uid = 1
$EXTRA
mail_location = maildir:$DIR/mail/%u
mail_plugins = \$mail_plugins
imap_capability = +IDLE
pop3_uidl_format = %08Xu%08Xv
passdb {
  driver = passwd-file
  args = scheme=PLAIN username_format=%u $DIR/users
}
userdb {
  driver = static
  args = uid=$MAIL_UID gid=$MAIL_GID home=$DIR/home/%u
}
service imap-login {
  chroot =
  inet_listener imap {
    port = 11143
  }
  inet_listener imaps {
    port = 11993
    ssl = yes
  }
}
service pop3-login {
  chroot =
  inet_listener pop3 {
    port = 11110
  }
  inet_listener pop3s {
    port = 11995
    ssl = yes
  }
}
service anvil {
  chroot =
}
service managesieve-login {
  chroot =
  inet_listener sieve {
    port = 14190
  }
}
protocol lda {
  mail_plugins = \$mail_plugins sieve
}
plugin {
  sieve = file:~/sieve;active=~/.dovecot.sieve
}
namespace inbox {
  inbox = yes
  separator = /
  mailbox Sent {
    special_use = \Sent
    auto = subscribe
  }
  mailbox Drafts {
    special_use = \Drafts
    auto = subscribe
  }
  mailbox Trash {
    special_use = \Trash
    auto = subscribe
  }
  mailbox Junk {
    special_use = \Junk
    auto = subscribe
  }
  mailbox Archive {
    special_use = \Archive
    auto = subscribe
  }
}
CONF

if ! pgrep -f "dovecot -c $DIR/dovecot.conf" >/dev/null; then
  dovecot -c "$DIR/dovecot.conf"
fi

if [ -f "$GREENMAIL_JAR" ] && ! { [ -f "$DIR/greenmail.pid" ] && kill -0 "$(cat "$DIR/greenmail.pid")" 2>/dev/null; }; then
  nohup java -Dgreenmail.setup.test.smtp -Dgreenmail.setup.test.imap -Dgreenmail.setup.test.smtps \
    -Dgreenmail.users=alice:secret@test.local,bob:secret@test.local \
    -Dgreenmail.auth.disabled=false -Dgreenmail.hostname=127.0.0.1 \
    -jar "$GREENMAIL_JAR" >"$DIR/greenmail.log" 2>&1 &
  echo $! > "$DIR/greenmail.pid"
fi

for port in 11143 3025; do
  for i in $(seq 1 80); do
    if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; then break; fi
    sleep 0.25
  done
done
echo "test servers running in $DIR"
