#!/usr/bin/env bash
set -euo pipefail
version="$(openssl version)"
mkdir -p tests/fixtures/openssl
capture() {
  local name="$1" host="$2" port="$3"
  {
    printf '# openssl_version: %s\n' "$version"
    printf '# source: %s:%s\n' "$host" "$port"
    timeout 20 openssl s_client -connect "$host:$port" -servername "$host" -showcerts < /dev/null 2>&1 || true
  } > "tests/fixtures/openssl/$name.txt"
}
capture cloudflare cloudflare.com 443
capture ato ato.gov.au 443
capture badssl badssl.com 443
capture self-signed self-signed.badssl.com 443
capture expired expired.badssl.com 443
capture sha1-intermediate sha1-intermediate.badssl.com 443
