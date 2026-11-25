#!/bin/sh
# auth-user-pass-verify script (via-file): $1 holds the username line and the
# password line. Every attempt is counted so the test can prove that the
# client does not retry rejected credentials. The expected credentials are
# written to /run/e2e/credentials by the test driver.
user=$(sed -n 1p "$1")
password=$(sed -n 2p "$1")
echo "attempt user=$user" >>/run/e2e/auth-attempts.log
[ "$user" = "$(sed -n 1p /run/e2e/credentials)" ] &&
  [ "$password" = "$(sed -n 2p /run/e2e/credentials)" ]
