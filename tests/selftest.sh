#!/usr/bin/env bash
# Builds a sample release, runs publish.sh on it (dry run) and checks the
# result the way the marketplace and Prusa Connect do: openssl verifies
# checksums.txt.sig over checksums.txt, every file matches its checksum, the
# archive is deterministic. Then feeds it the releases the marketplace refuses.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
publish="$here/../publish.sh"

openssl genpkey -algorithm RSA -out "$work/key.pem" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl pkey -in "$work/key.pem" -pubout -out "$work/pub.pem"

# An executable header: enough of one for the platform check.
elf() { # <file> <e_machine as two little-endian bytes in \x form>
  { printf '\177ELF\002\001\001'; head -c 11 /dev/zero; printf '%b' "$2"; head -c 200 /dev/zero; } >"$1"
}
macho_arm64() { { printf '\317\372\355\376\014\000\000\001'; head -c 200 /dev/zero; } >"$1"; }
pe_amd64() {
  { printf 'MZ'; head -c 58 /dev/zero; printf '\100\000\000\000'; printf 'PE\000\000\144\206'; head -c 200 /dev/zero; } >"$1"
}

sample() { # <dir>: a release with a process half and a browser half
  mkdir -p "$1/ui/locales"
  cat >"$1/module.yaml" <<'EOF'
name: hello
title: Hello
kind: sink
version: 1.2.0 # the release
license: MIT
contract_major: 1
platforms:
  - linux_amd64
  - linux_arm64
  - darwin_arm64
  - windows_amd64
ui:
  entry: ui/index.js
  library: ">=0.0.1 <1.0.0"
EOF
  elf "$1/hello_linux_amd64" '\076\000'
  elf "$1/hello_linux_arm64" '\267\000'
  macho_arm64 "$1/hello_darwin_arm64"
  pe_amd64 "$1/hello_windows_amd64.exe"
  echo 'export default {}' >"$1/ui/index.js"
  echo '{"hello":"Hello"}' >"$1/ui/locales/en.json"
  echo '# Hello' >"$1/README.md"
}

common=("INPUT_PRIVATE_KEY=$(cat "$work/key.pem")" INPUT_DRY_RUN=true INPUT_MODULE=github.com/acme/hello)

run() { # <release-dir> <out-dir> [env...]
  local dir="$1" out="$2"
  shift 2
  mkdir -p "$out"
  env "${common[@]}" "INPUT_PATH=$dir" "RUNNER_TEMP=$out" "GITHUB_OUTPUT=$out/outputs" "$@" "$publish"
}

sample "$work/ok"
run "$work/ok" "$work/a" GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.2.0 2>"$work/log" || { cat "$work/log" >&2; exit 1; }
grep -q '^extension-id=com.github.aux.acme.hello$' "$work/a/outputs" || { echo "FAIL: extension id" >&2; exit 1; }
archive="$(grep '^archive=' "$work/a/outputs" | cut -d= -f2-)"
[ -f "$archive" ] || { echo "FAIL: no archive" >&2; exit 1; }
echo "ok: dry run packs $(basename "$archive")"

# The builder passes the extension's folder: with no module input, the module
# path comes from its go.mod, so each extension of a repository has its own.
mkdir -p "$work/mono/extensions/spools"
printf 'module github.com/acme/tools/extensions/spools\n\ngo 1.26\n' >"$work/mono/extensions/spools/go.mod"
run "$work/ok" "$work/m" INPUT_MODULE= "INPUT_MODULE_DIR=$work/mono/extensions/spools" 2>"$work/log" || { cat "$work/log" >&2; exit 1; }
grep -q '^extension-id=com.github.aux.acme.tools.extensions.spools$' "$work/m/outputs" ||
  { echo "FAIL: module path from go.mod" >&2; cat "$work/m/outputs" >&2; exit 1; }
echo "ok: module path from the extension's go.mod"

# The two phases the action runs around the attestation: pack stops before
# uploading and leaves what the upload needs; upload goes on from there (here
# it stops at the OIDC token, which only a workflow run has).
run "$work/ok" "$work/p" INPUT_DRY_RUN=false INPUT_PHASE=pack 2>"$work/log" || { cat "$work/log" >&2; exit 1; }
grep -q '^status=packed$' "$work/p/outputs" || { echo "FAIL: pack phase status" >&2; exit 1; }
[ -f "$work/p/publish-state.sh" ] || { echo "FAIL: pack phase left no state" >&2; exit 1; }
if run "$work/ok" "$work/p" INPUT_DRY_RUN=false INPUT_PHASE=upload 2>"$work/log"; then
  echo "FAIL: upload without a token should fail" >&2; exit 1
fi
grep -q 'no OIDC token available' "$work/log" || { echo "FAIL: upload phase did not reach the upload" >&2; cat "$work/log" >&2; exit 1; }
echo "ok: pack, then upload"
[ ! -e "$work/ok/checksums.txt" ] || { echo "FAIL: the author's directory was written to" >&2; exit 1; }
echo "ok: the release directory is left as it was"

mkdir "$work/x"
tar -xzf "$archive" -C "$work/x"
openssl base64 -d -A -in "$work/x/checksums.txt.sig" -out "$work/sig.bin"
openssl dgst -sha256 -verify "$work/pub.pem" -signature "$work/sig.bin" "$work/x/checksums.txt" >/dev/null
echo "ok: signature verifies"
(cd "$work/x" && if command -v sha256sum >/dev/null; then sha256sum -c --quiet checksums.txt; else shasum -a 256 -c --quiet checksums.txt; fi)
lines="$(wc -l <"$work/x/checksums.txt" | tr -d ' ')"
[ "$lines" = "8" ] || { echo "FAIL: checksums.txt lists $lines files, expected 8" >&2; exit 1; }
echo "ok: checksums.txt covers every file"
listing="$(tar -tvzf "$archive")"
grep -q 'rwxr-xr-x.*hello_linux_amd64$' <<<"$listing" || { echo "FAIL: binary not 755" >&2; exit 1; }
grep -q 'rw-r--r--.*ui/index.js$' <<<"$listing" || { echo "FAIL: ui file not 644" >&2; exit 1; }
subjects="$(grep '^subjects=' "$work/a/outputs" | cut -d= -f2-)"
[ "$(wc -l <"$subjects" | tr -d ' ')" = "9" ] || { echo "FAIL: subjects" >&2; exit 1; }
echo "ok: modes and attestation subjects"

# The same input packs to the same bytes (the signature is deterministic too:
# RSA PKCS#1 v1.5 has no randomness).
run "$work/ok" "$work/b" 2>/dev/null
cmp -s "$archive" "$work/b/hello-1.2.0.tar.gz" || { echo "FAIL: the archive is not deterministic" >&2; exit 1; }
echo "ok: deterministic archive"

# A browser bundle alone is a release too.
mkdir -p "$work/ui-only/ui"
printf 'name: board\nversion: 0.1.0\nlicense: Apache-2.0\nui:\n  entry: ui/index.js\n' >"$work/ui-only/module.yaml"
echo 'export default {}' >"$work/ui-only/ui/index.js"
run "$work/ui-only" "$work/c" 2>/dev/null
echo "ok: a browser-only release"

extra=(GITHUB_REF_TYPE=branch)
expect_fail() { # <name> <expected message part> <setup...>
  local name="$1" expected="$2"
  shift 2
  rm -rf "$work/bad" "$work/badout"
  sample "$work/bad"
  (cd "$work/bad" && eval "$*")
  if run "$work/bad" "$work/badout" "${extra[@]}" >"$work/log" 2>&1; then
    echo "FAIL: $name should have failed" >&2
    exit 1
  fi
  grep -q -- "$expected" "$work/log" || { echo "FAIL: $name: expected '$expected' in:" >&2; cat "$work/log" >&2; exit 1; }
  echo "ok: refuses $name"
}

expect_fail "a missing binary" "linux_arm64 is declared" rm hello_linux_arm64
expect_fail "a binary for another platform" "the header says elf/amd64, the name says linux_arm64" cp hello_linux_amd64 hello_linux_arm64
expect_fail "a script posing as a binary" "is not an ELF, Mach-O or PE" "printf '#!/bin/sh\nrm -rf ~\n' > hello_linux_amd64"
expect_fail "an unexpected file" "install.sh: only module.yaml" "echo x > install.sh"
expect_fail "a binary hidden in ui/" "ui/helper: only module.yaml" "cp hello_linux_amd64 ui/helper"
expect_fail "an executable ui file" "nothing under ui/ may be executable" chmod +x ui/index.js
expect_fail "a hidden file" "hidden files" "echo x > .env"
expect_fail "a symbolic link" "symbolic links" "ln -s /etc/passwd ui/passwd.json"
expect_fail "a committed private key" "contains a private key" "cp '$work/key.pem' ui/key.json"
expect_fail "broken JSON" "ui/locales/en.json is not valid JSON" "echo '{' > ui/locales/en.json"
expect_fail "a missing ui entry" "ui.entry names ui/index.js" rm ui/index.js
expect_fail "a loose version" "exact semantic version" "sed -i.bak 's/^version: .*/version: latest/' module.yaml && rm module.yaml.bak"
expect_fail "no license" "module.yaml has no license" "sed -i.bak '/^license:/d' module.yaml && rm module.yaml.bak"
extra=(GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.3.0)
expect_fail "a tag for another version" "does not match module.yaml version" true
extra=(GITHUB_REF_TYPE=branch INPUT_MODULE=github.com/Acme/Hello)
expect_fail "a module path that is no namespace" "is not a lowercase DNS label" true
