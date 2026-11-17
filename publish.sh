#!/usr/bin/env bash
# Sign a Prusa Connect extension release and publish it to the Prusa Plugin Marketplace.
#
# 1. Check the release directory the way the marketplace does (lib/release.py):
#    module.yaml, one binary per declared platform with a matching executable
#    header, the browser bundle, nothing else. Check the tag against the version.
# 2. Write checksums.txt (sha256sum format over every file) and sign it into
#    checksums.txt.sig with the author's RSA key: the bytes
#    `openssl dgst -sha256 -sign` writes, base64. Prusa Connect and the
#    marketplace verify the same bytes.
# 3. Pack a deterministic .tar.gz.
# 4. Ask GitHub for this run's OIDC token, audience = the marketplace origin,
#    and upload. The marketplace checks the token's repository, workflow and
#    environment against the extension's trusted publishers; no other
#    credential exists. The token also names the commit, so the marketplace
#    knows which source the release came from.
#
# Inputs come as INPUT_* environment variables (see action.yml), so the script
# also runs outside Actions for testing.
set -euo pipefail

fail() {
  echo "::error::$*" >&2
  exit 1
}
note() { echo "$*" >&2; }
output() { if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "$1=$2" >>"$GITHUB_OUTPUT"; fi; }
summary() { if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "$*" >>"$GITHUB_STEP_SUMMARY"; fi; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_py() { python3 -I "$here/lib/release.py" "$@"; }

for tool in jq openssl curl python3; do
  command -v "$tool" >/dev/null || fail "$tool is required on the runner"
done

src="${INPUT_PATH:-release}"
marketplace="${INPUT_MARKETPLACE_URL:-https://plugin-marketplace.prusa3d.com}"
marketplace="${marketplace%/}"
# The audience is the marketplace's origin: scheme and host, no path.
origin="$(printf '%s\n' "$marketplace" | sed -n 's|^\(https\{0,1\}://[^/]*\).*|\1|p')"
[ -n "$origin" ] || fail "marketplace-url '$marketplace' is not an http(s) address"
[ -d "$src" ] || fail "no release directory '$src' (set the path input to the directory your build wrote)"
[ -n "${INPUT_PRIVATE_KEY:-}" ] || fail "private-key is empty: the signing key secret did not reach this step. Pass it as private-key: \${{ secrets.PRUSA_CONNECT_EXTENSION_SIGNING_KEY }} (with the builder: under secrets: by name; secrets: inherit does not cross organisations)"

# The extension's identity. By default the module path in the extension's
# go.mod (the builder passes its folder), else the repository's own address,
# which is also what an operator types to install it from source.
module="${INPUT_MODULE:-}"
if [ -z "$module" ] && [ -n "${INPUT_MODULE_DIR:-}" ] && [ -f "$INPUT_MODULE_DIR/go.mod" ]; then
  module="$(sed -n 's/^module[[:space:]]\{1,\}//p' "$INPUT_MODULE_DIR/go.mod" | head -1 | tr -d '"' | tr -d '\r')"
fi
if [ -z "$module" ]; then
  [ -n "${GITHUB_REPOSITORY:-}" ] || fail "module is empty and GITHUB_REPOSITORY is not set"
  module="github.com/$(printf '%s' "$GITHUB_REPOSITORY" | tr '[:upper:]' '[:lower:]')"
fi
extension_id="$(release_py namespace "$module")" || fail "module '$module' cannot name an extension"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Work on a copy: the author's directory keeps no stale signature, and a file
# changed after the check cannot slip into the archive.
# The action runs two phases, so the provenance attestation is recorded
# before anything is uploaded and a release never reaches the marketplace
# without it: "pack" checks, signs and packs, and leaves what the upload needs
# in $RUNNER_TEMP; "upload" uploads that. "all" (the default) does both.
phase="${INPUT_PHASE:-all}"
case "$phase" in all | pack | upload) ;; *) fail "INPUT_PHASE must be all, pack or upload" ;; esac
out_dir="${RUNNER_TEMP:-$PWD}"
state="$out_dir/publish-state.sh"

if [ "$phase" = upload ]; then
  [ -f "$state" ] || fail "nothing was packed: run the pack phase first"
  # shellcheck source=/dev/null
  . "$state"
  changelog="$(cat "$out_dir/publish-changelog.md")"
else
  mkdir "$work/release"
  cp -R "$src"/. "$work/release"/
  rm -f "$work/release/checksums.txt" "$work/release/checksums.txt.sig"

  facts="$(release_py checksum "$work/release")" || fail "the release in '$src' is not one the marketplace accepts (see above)"
  name="$(jq -r .name <<<"$facts")"
  version="$(jq -r .version <<<"$facts")"
  output extension-id "$extension_id"
  output version "$version"
  note "Extension $extension_id ($name) $version from module $module"
  note "Platforms: $(jq -r 'if (.platforms|length)==0 then "none (browser bundle only)" else .platforms|join(", ") end' <<<"$facts")"
  note "Browser bundle: $(jq -r 'if .ui then "yes" else "no" end' <<<"$facts")"

  # A release tag names the version it ships. Anything before the version is a
  # prefix: v1.2.0, spools/v1.2.0, com.example.spools@1.2.0.
  if [ "${INPUT_CHECK_VERSION:-true}" = "true" ] && [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
    tag="${GITHUB_REF_NAME:-}"
    prefix="${tag%"$version"}"
    if [ "$prefix" = "$tag" ] || [[ -n "$prefix" && ! "$prefix" =~ (^|[/@_-])v?$ ]]; then
      fail "tag '$tag' does not match module.yaml version $version (expected e.g. v$version)"
    fi
  fi

  event="${GITHUB_EVENT_PATH:-}"
  release_field() {
    if [ -n "$event" ] && [ -f "$event" ]; then jq -r "$1 // empty" "$event"; fi
  }

  channel="${INPUT_CHANNEL:-}"
  if [ -z "$channel" ]; then
    channel=stable
    if [ "$(release_field '.release.prerelease')" = "true" ]; then channel=beta; fi
  fi
  case "$channel" in stable | beta) ;; *) fail "channel must be stable or beta, got '$channel'" ;; esac

  changelog="${INPUT_CHANGELOG:-}"
  [ -n "$changelog" ] || changelog="$(release_field '.release.body')"

  note "Release contents:"
  sed 's/^[0-9a-f]*  /  /' "$work/release/checksums.txt" >&2

  # ── signature ────────────────────────────────────────────────────────
  key="$work/key.pem"
  (umask 077 && printf '%s\n' "$INPUT_PRIVATE_KEY" >"$key")
  key_text="$(openssl pkey -in "$key" -noout -text 2>/dev/null)" || fail "private-key is not a PEM private key"
  # The marketplace registers RSA keys of 2048 bits or more only; anything else
  # would sign fine here and fail verification there with a vaguer message.
  grep -qi '^modulus:' <<<"$key_text" || fail "private-key must be an RSA key (the marketplace verifies RSA signatures only)"
  bits="$(head -1 <<<"$key_text" | grep -o '[0-9]\+' | head -1)"
  [ "${bits:-0}" -ge 2048 ] || fail "private-key must be RSA with at least 2048 bits, got ${bits:-unknown}"
  openssl dgst -sha256 -sign "$key" -out "$work/signature.bin" "$work/release/checksums.txt"
  openssl pkey -in "$key" -pubout -out "$work/public.pem"
  rm -f "$key"
  openssl dgst -sha256 -verify "$work/public.pem" -signature "$work/signature.bin" \
    "$work/release/checksums.txt" >/dev/null || fail "the signature does not verify against its own key"
  { openssl base64 -A <"$work/signature.bin"; echo; } >"$work/release/checksums.txt.sig"
  fingerprint="$(openssl pkey -pubin -in "$work/public.pem" -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)"
  note "Signed with key $fingerprint"

  # ── archive ──────────────────────────────────────────────────────────
  archive="$out_dir/$name-$version.tar.gz"
  packed="$(release_py pack "$work/release" "$archive")" || fail "the release could not be packed"
  sha256="$(openssl dgst -sha256 -r "$archive" | cut -d' ' -f1)"
  output archive "$archive"
  output sha256 "$sha256"
  # The attestation subjects: the archive, and every file in it by its path.
  subjects="$out_dir/$name-$version.subjects.txt"
  { printf '%s  %s\n' "$sha256" "$(basename "$archive")"; cat "$work/release/checksums.txt"; } >"$subjects"
  output subjects "$subjects"
  note "Archive $archive ($(jq -r .size <<<"$packed") bytes, sha256 $sha256)"

  if [ "${INPUT_DRY_RUN:-false}" = "true" ]; then
    note "Dry run: not uploading."
    output status dry-run
    summary "### $extension_id $version signed (dry run, not uploaded)"
    exit 0
  fi

  if [ "$phase" = pack ]; then
    printf '%s' "$changelog" >"$out_dir/publish-changelog.md"
    declare -p module extension_id name version channel archive sha256 fingerprint >"$state"
    output status packed
    exit 0
  fi
fi

# ── upload ───────────────────────────────────────────────────────────
if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
  fail "no OIDC token available: give the job 'permissions: id-token: write'"
fi
audience="$(jq -rn --arg v "$origin" '$v|@uri')"
# Credentials go to curl in header files, not arguments: on a shared
# self-hosted runner other processes can read a command line.
(umask 077 && printf 'Authorization: bearer %s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" >"$work/oidc.h")
token="$(curl -sSf -H @"$work/oidc.h" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$audience" | jq -r '.value // empty')" ||
  fail "could not get an OIDC token from GitHub"
[ -n "$token" ] || fail "GitHub answered no OIDC token for the audience $origin"
echo "::add-mask::$token"
(umask 077 && printf 'Authorization: Bearer %s\n' "$token" >"$work/auth.h")

printf '%s' "$changelog" >"$work/changelog.md"

if [ -n "${INPUT_SOURCE:-}" ]; then
  # A verified build (.github/workflows/publish.yml): the release and the
  # source of the commit it was built from, in one multipart request. The
  # marketplace accepts it only with this workflow named in the token.
  [ -f "$INPUT_SOURCE" ] || fail "no source archive '$INPUT_SOURCE'"
  source_bytes="$(wc -c <"$INPUT_SOURCE" | tr -d ' ')"
  [ "$source_bytes" -le $((50 * 1024 * 1024)) ] ||
    fail "the repository's source is $source_bytes bytes, at most 50 MB are accepted; keep large assets out of it"
  endpoint="$marketplace/api/publish/v1/connect/builds"
  status="$(curl -sS -o "$work/response.json" -D "$work/headers" -w '%{http_code}' -X POST \
    -H @"$work/auth.h" \
    --form-string "module=$module" --form-string "channel=$channel" \
    -F "changelog=<$work/changelog.md" \
    -F "archive=@$archive;type=application/gzip" \
    -F "source=@$INPUT_SOURCE;type=application/gzip" \
    "$endpoint")" ||
    fail "could not reach $marketplace"
else
  base64 <"$archive" | tr -d '\n' >"$work/archive.b64"
  # The keys are quoted: `module` is a keyword in jq 1.6.
  jq -n --arg mod "$module" --arg channel "$channel" \
    --rawfile archive "$work/archive.b64" --rawfile changelog "$work/changelog.md" \
    '{"module": $mod, "archive": $archive, "channel": $channel} + (if $changelog == "" then {} else {"changelog": $changelog} end)' \
    >"$work/body.json"

  endpoint="$marketplace/api/publish/v1/connect/releases"
  status="$(curl -sS -o "$work/response.json" -D "$work/headers" -w '%{http_code}' -X POST \
    -H @"$work/auth.h" -H 'Content-Type: application/json' \
    --data-binary "@$work/body.json" "$endpoint")" ||
    fail "could not reach $marketplace"
fi

case "$status" in
  201) ;;
  409)
    if [ "${INPUT_ALLOW_EXISTING:-false}" = "true" ]; then
      note "The marketplace already has $extension_id $version; nothing was uploaded."
      output status exists
      exit 0
    fi
    fail "the marketplace already has $extension_id $version. Raise the version in module.yaml to release again"
    ;;
  *)
    message="$(jq -r '.error // empty' "$work/response.json" 2>/dev/null || true)"
    if [ -z "$message" ]; then
      # Not the marketplace's JSON: something in front of it (a proxy, a
      # firewall) answered. Name it instead of dumping its HTML.
      title="$(tr -d '\n' <"$work/response.json" | grep -o '<title>[^<]*' | head -1 | sed 's/<title>//' || true)"
      message="the answer did not come from the marketplace${title:+ (\"$title\")}"
    fi
    fail "the marketplace refused the release ($status): $message"
    ;;
esac

url="$(jq -r '.url // empty' "$work/response.json")"
output url "$url"
output status in_review
note "Uploaded $extension_id $version to the $channel channel; it waits for review: $url"
summary "### $extension_id $version submitted to the Plugin Marketplace"
summary ""
summary "Channel \`$channel\`, archive sha256 \`$sha256\`, signed with key \`${fingerprint:0:16}…\`."
summary "Every Connect release is scanned and reviewed by a person before operators can install it: [follow it in the author console]($url)."
