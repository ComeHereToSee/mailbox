#!/usr/bin/env bash
# Regenerates the interoperability fixtures used by the `crypto` tests.
#
#   cd core/crates/mailcore/src/crypto/testdata && ./gen.sh
#
# Needs the `openssl` (3.x) and `gpg` (2.2+) command line tools. The Rust code never calls them;
# they are only used here, once, to produce messages written by real implementations:
#
# S/MIME (OpenSSL):
#   alice.p12 (password "alice-pass"), bob.p12 ("bob-pass"): RSA-2048 self-signed e-mail certificates
#   (OpenSSL 3 defaults: PBES2/PBKDF2/AES-256-CBC, HMAC-SHA256), bob_legacy.p12: the same as bob.p12
#   in the legacy format (`-legacy`: 3DES key bag, RC2-40 certificate bag, HMAC-SHA1) that macOS
#   Keychain and older Windows exports use, bob.crt: Bob's certificate alone (PEM).
#   openssl_signed.eml         multipart/signed (detached) from Bob, `openssl smime -sign`
#   openssl_opaque.eml         application/pkcs7-mime signed-data from Bob, `openssl smime -sign -nodetach`
#   openssl_encrypted.eml      enveloped-data to Alice, AES-256-CBC, `openssl smime -encrypt`
#   openssl_ber_3des.eml       enveloped-data to Alice, 3DES, streamed (indefinite-length BER)
#   openssl_signed_encrypted.eml  signed by Bob, then encrypted to Alice (AES-128-CBC)
#   openssl_oaep_pss.eml       `openssl cms`: RSA-PSS signature by Bob, RSA-OAEP key transport to Alice
#   openssl_ecdsa_signed.eml   multipart/signed by Eve's ECDSA P-256 certificate (embedded in the message)
#
# OpenPGP (GnuPG):
#   gpg_carol_sec.asc: Carol's RSA-2048 key (passphrase "carol-pass", encryption subkey),
#   gpg_dave_pub.asc / gpg_dave_sec.asc: Dave's Ed25519 + Cv25519 key (no passphrase).
#   gpg_encrypted.eml          PGP/MIME, signed by Dave and encrypted to Carol in one OpenPGP message
#   gpg_signed.eml             PGP/MIME multipart/signed by Dave (`gpg --detach-sign`)
#   gpg_clearsigned.eml        inline `gpg --clearsign` by Dave
#   gpg_inline_encrypted.eml   inline `gpg --encrypt --sign` from Dave to Carol
set -euo pipefail
OUT="$(pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

crlf() { sed 's/$/\r/'; }

# ---------------------------------------------------------------- S/MIME keys
mkcert() { # name email cn
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.crt" -days 36500 -utf8 \
    -subj "/CN=$3/emailAddress=$2" -addext "subjectAltName=email:$2" \
    -addext "keyUsage=digitalSignature,keyEncipherment" -addext "extendedKeyUsage=emailProtection" 2>/dev/null
  openssl pkcs12 -export -inkey "$1.key" -in "$1.crt" -out "$1.p12" -passout "pass:$1-pass" -name "$1"
}
mkcert alice alice@example.com "爱丽丝 Alice"
mkcert bob bob@example.org "Bob Wang"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout eve.key -out eve.crt -days 36500 \
  -subj "/CN=Eve/emailAddress=eve@example.net" -addext "subjectAltName=email:eve@example.net" 2>/dev/null

# The protected MIME entity: text + attachment.
{
  printf 'Content-Type: multipart/mixed; boundary="inner-b"\n\n'
  printf -- '--inner-b\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n'
  printf '你好，这是来自 OpenSSL 的测试邮件。\n'
  printf -- '--inner-b\nContent-Type: application/pdf; name="报告.pdf"\nContent-Disposition: attachment; filename="report.pdf"\nContent-Transfer-Encoding: base64\n\n'
  printf '%%PDF-1.4 test' | base64
  printf -- '--inner-b--\n'
} > entity.txt

hdr() { printf 'From: Bob Wang <bob@example.org>\nTo: alice@example.com\nSubject: %s\nDate: Thu, 22 Oct 2026 10:00:00 +0800\nMessage-ID: <%s@example.org>\n' "$1" "$2"; }

{ hdr "openssl signed" s1; openssl smime -sign -in entity.txt -signer bob.crt -inkey bob.key; } > "$OUT/openssl_signed.eml"
{ hdr "openssl opaque" s2; openssl smime -sign -nodetach -in entity.txt -signer bob.crt -inkey bob.key; } > "$OUT/openssl_opaque.eml"
{ hdr "openssl encrypted" s3; openssl smime -encrypt -aes256 -in entity.txt alice.crt; } > "$OUT/openssl_encrypted.eml"
{ hdr "openssl ber" s4; openssl smime -encrypt -des3 -stream -in entity.txt alice.crt; } > "$OUT/openssl_ber_3des.eml"
openssl smime -sign -in entity.txt -signer bob.crt -inkey bob.key > signed.txt
{ hdr "openssl signed+encrypted" s5; openssl smime -encrypt -aes128 -in signed.txt alice.crt; } > "$OUT/openssl_signed_encrypted.eml"
openssl cms -sign -in entity.txt -signer bob.crt -inkey bob.key -keyopt rsa_padding_mode:pss -md sha256 > pss.txt
{ hdr "openssl oaep pss" s6; openssl cms -encrypt -aes-256-cbc -recip alice.crt -keyopt rsa_padding_mode:oaep -in pss.txt; } \
  > "$OUT/openssl_oaep_pss.eml"
{ printf 'From: Eve <eve@example.net>\nTo: alice@example.com\nSubject: ecdsa\n'; \
  openssl smime -sign -in entity.txt -signer eve.crt -inkey eve.key; } > "$OUT/openssl_ecdsa_signed.eml"
openssl pkcs12 -export -legacy -inkey bob.key -in bob.crt -out bob_legacy.p12 -passout pass:bob-pass -name bob
cp alice.p12 bob.p12 bob_legacy.p12 bob.crt "$OUT/"

# ---------------------------------------------------------------- OpenPGP
export GNUPGHOME="$WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"
G=(gpg --batch --yes --utf8-strings --pinentry-mode loopback --trust-model always)
"${G[@]}" --passphrase carol-pass --quick-gen-key "Carol <carol@example.net>" rsa2048 cert,sign never
CAROL=$("${G[@]}" --list-keys --with-colons carol@example.net | awk -F: '/^fpr/ {print $10; exit}')
"${G[@]}" --passphrase carol-pass --quick-add-key "$CAROL" rsa2048 encr never
"${G[@]}" --passphrase '' --quick-gen-key "Dave 戴 <dave@example.net>" ed25519 cert,sign never
DAVE=$("${G[@]}" --list-keys --with-colons dave@example.net | awk -F: '/^fpr/ {print $10; exit}')
"${G[@]}" --passphrase '' --quick-add-key "$DAVE" cv25519 encr never
"${G[@]}" --passphrase carol-pass --armor --export-secret-keys "$CAROL" > "$OUT/gpg_carol_sec.asc"
"${G[@]}" --armor --export "$DAVE" > "$OUT/gpg_dave_pub.asc"
"${G[@]}" --passphrase '' --armor --export-secret-keys "$DAVE" > "$OUT/gpg_dave_sec.asc"

crlf < entity.txt > entity.crlf
pgphdr() { printf 'From: Dave <dave@example.net>\r\nTo: carol@example.net\r\nSubject: %s\r\nMIME-Version: 1.0\r\n' "$1"; }

"${G[@]}" --passphrase '' -u "$DAVE" -r "$CAROL" --armor --sign --encrypt -o enc.asc entity.crlf
{ pgphdr "gpg encrypted"
  printf 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="pgp-b"\r\n\r\n'
  printf -- '--pgp-b\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n'
  printf -- '--pgp-b\r\nContent-Type: application/octet-stream; name="encrypted.asc"\r\n\r\n'
  crlf < enc.asc
  printf -- '\r\n--pgp-b--\r\n'; } > "$OUT/gpg_encrypted.eml"

# The signed part is exactly entity.crlf without its final CRLF (that one belongs to the boundary).
head -c -2 entity.crlf > signed.part
"${G[@]}" --passphrase '' -u "$DAVE" --armor --detach-sign -o sig.asc signed.part
{ pgphdr "gpg signed"
  printf 'Content-Type: multipart/signed; micalg=pgp-sha512; protocol="application/pgp-signature"; boundary="sig-b"\r\n\r\n'
  printf -- '--sig-b\r\n'; cat signed.part
  printf -- '\r\n--sig-b\r\nContent-Type: application/pgp-signature; name="signature.asc"\r\n\r\n'
  crlf < sig.asc
  printf -- '\r\n--sig-b--\r\n'; } > "$OUT/gpg_signed.eml"

printf '你好 Carol，\n这是一封明文签名的邮件。\n- 以短横线开头的行\n' > clear.txt
"${G[@]}" --passphrase '' -u "$DAVE" --clearsign -o clear.asc clear.txt
{ pgphdr "gpg clearsigned"; printf 'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n'
  crlf < clear.asc; } > "$OUT/gpg_clearsigned.eml"

printf '内联加密的正文\n第二行\n' > inline.txt
"${G[@]}" --passphrase '' -u "$DAVE" -r "$CAROL" --armor --sign --encrypt -o inline.asc inline.txt
{ pgphdr "gpg inline"; printf 'Content-Type: text/plain; charset=us-ascii\r\n\r\n'
  crlf < inline.asc; } > "$OUT/gpg_inline_encrypted.eml"
echo "fixtures written to $OUT"
