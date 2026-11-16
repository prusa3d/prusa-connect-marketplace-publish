# Publish a Prusa Connect extension

[![CI](https://github.com/prusa3d/prusa-connect-marketplace-publish/actions/workflows/ci.yml/badge.svg)](https://github.com/prusa3d/prusa-connect-marketplace-publish/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> [!NOTE]
> The Prusa Plugin Marketplace is in beta.

GitHub Action that checks a [Prusa Connect](https://github.com/prusa3d/prusa-connect) extension
release, signs it and publishes it to the
[Prusa Plugin Marketplace](https://plugin-marketplace.prusa3d.com) with **trusted publishing**:
the workflow proves which repository and workflow it is with the OIDC token GitHub issues to the
run. There is no marketplace password or API key to store.

Every release is still reviewed before it is public. This action only submits it.

A complete extension repository to copy:
[prusa3d/prusa-connect-extension-example](https://github.com/prusa3d/prusa-connect-extension-example).

## Verified build (`publish.yml`)

The way to publish from now on. Instead of building the release yourself and handing it to the
action, call the builder, a reusable workflow. It builds the extension from the commit the run is
for and sends the marketplace the release together with that commit's source:

```yaml title=".github/workflows/release.yml"
name: Publish to Plugin Marketplace
on:
  release:
    types: [published]
jobs:
  publish:
    uses: prusa3d/prusa-connect-marketplace-publish/.github/workflows/publish.yml@v1
    with:
      path: .                       # the extension's folder: module.yaml, go.mod, ui/
      bundle-command: make ui-build # what builds ui/dist (default: pnpm build in ui/)
      core-ref: main                # Prusa Connect into .core/, until the SDK is published
    secrets: inherit                # PRUSA_CONNECT_EXTENSION_SIGNING_KEY from the environment
    permissions:
      contents: read
      id-token: write
      attestations: write
```

- **The program** is built by the builder's own steps, `go build -trimpath` for every platform in
  `module.yaml`, with no cgo, no Makefile and no `go generate`. None of your code runs there.
- **The browser bundle** is built by your `bundle-command` in a job of its own, which gets no
  secret and no token. Only its `ui/` is used; `module.yaml` comes from the commit.
- **Signing and upload** happen in a third job, in the environment `release` (input
  `environment`), with the key and the OIDC token. The token names this workflow, and the
  marketplace accepts a verified build only with it, so no other build can pass for one.
- **The source** of the whole repository at that commit goes with the release, so the review reads
  code, not only binaries. At most 50 MB.
- **A public repository.** The builder records a GitHub build provenance attestation before it
  uploads, and GitHub records attestations only for public repositories (or on GitHub Enterprise
  Cloud). From a private repository the run stops before the upload.
- **`core-ref`** checks Prusa Connect out into `.core/` while the SDK is not published. While
  `prusa3d/prusa-connect` is private, pass a read-only deploy key of it as the secret
  `PRUSA_CONNECT_DEPLOY_KEY`.
- **Several extensions in one repository**: call the builder once per folder (`path`). Each
  extension's id comes from its folder's `go.mod`; tag releases `<folder>/v<version>`.
- **CI**: `dry-run: true` builds, checks and signs with a throwaway key, waits for no reviewer and
  uploads nothing.

The composite action below (`uses: prusa3d/prusa-connect-marketplace-publish@v1`) keeps working for
now. Once every extension publishes through the builder, the marketplace accepts Connect releases
from the builder alone.

## What it does (the composite action)

1. Checks the release directory the way the marketplace does: `module.yaml` with its `license`
   (required), one binary per
   platform the manifest declares, named `<name>_<goos>_<goarch>` (with `.exe` on Windows),
   with an executable header that matches its platform, and the browser bundle under `ui/`
   when the manifest has one. Hidden files and symbolic links are refused.
2. When the run is for a tag, checks that the tag ends with the `version` in `module.yaml`:
   `v1.2.0`, `1.2.0` or `spools/v1.2.0`.
3. Writes `checksums.txt` over every file and signs it into `checksums.txt.sig` with your key.
   Prusa Connect and the marketplace verify the same bytes.
4. Packs a deterministic `.tar.gz`.
5. Records a GitHub build provenance attestation for the archive and every binary (a public
   repository only, see above). A failed attestation stops the run before the upload.
6. Uploads it with the run's OIDC token.

## Setup

1. **Signing key.** Create an RSA key pair (2048 bits or more) and register the public key in the
   author console under *Signing keys*:

   ```bash
   openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
   openssl rsa -pubout -in private_key.pem -out public_key.pem
   ```

   Store the private key as a secret, ideally in a protected environment:

   ```bash
   gh secret set PRUSA_CONNECT_EXTENSION_SIGNING_KEY --env release < private_key.pem
   ```

   > [!WARNING]
   > Whoever has the private key can sign releases the marketplace and Prusa Connect accept as
   > yours. Never commit it. Keep a backup in a password manager: the marketplace holds only the
   > public key and GitHub never shows a secret again. If it leaks, revoke it in the author
   > console right away and register a new one.

2. **Trusted publisher.** In the author console under *Trusted publishing*, add the extension id,
   `owner/repository`, the workflow file name and, if you use one, the GitHub environment.

3. **Workflow.** Build the release directory, then call the action:

   ```yaml
   name: Release
   on:
     release:
       types: [published]
   permissions:
     contents: read
     id-token: write     # the run proves its identity with an OIDC token
     attestations: write # the build provenance attestation
   jobs:
     publish:
       runs-on: ubuntu-latest
       environment: release
       steps:
         - uses: actions/checkout@v5
         # ... build every platform into release/, e.g. `make release`
         - uses: prusa3d/prusa-connect-marketplace-publish@v1
           with:
             path: release
             private-key: ${{ secrets.PRUSA_CONNECT_EXTENSION_SIGNING_KEY }}
   ```

4. **Release.** Publish a GitHub release whose tag ends with the version in `module.yaml`. A
   pre-release goes to the beta channel, and the release notes become the changelog.

## Extension id

The id is derived from the module path: `github.com/acme/spools` becomes
`com.github.aux.acme.spools`. By default the module path is `github.com/<this repository>`, in
lowercase, which is also what an operator types to install the extension from source. Set
`module` when the extension lives elsewhere, for example in a repository with several extensions.

## Inputs

| input | default | what it is |
|---|---|---|
| `path` | `release` | the release directory your build wrote, relative to the workspace |
| `module` | `github.com/<this repository>` | the module path the extension id is derived from |
| `private-key` | required | the RSA private key (PEM) that signs `checksums.txt` |
| `marketplace-url` | `https://plugin-marketplace.prusa3d.com` | the marketplace to publish to |
| `channel` | beta for a pre-release, stable otherwise | `stable` or `beta` |
| `changelog` | the GitHub release body | release notes in Markdown |
| `check-version` | `true` | require a tag to end with the version in `module.yaml` |
| `attest` | `true` | record a build provenance attestation. Needs `attestations: write` |
| `allow-existing` | `false` | treat a version the marketplace already has as success, for re-runs |
| `dry-run` | `false` | check, sign and pack, but upload nothing |

## Outputs

| output | what it is |
|---|---|
| `extension-id` | the id derived from the module path |
| `version` | the version from `module.yaml` |
| `archive` | the path of the signed `.tar.gz` |
| `sha256` | the archive's SHA-256. Prusa Connect refuses a download with any other |
| `status` | `in_review`, `exists` or `dry-run` |
| `subjects` | a `sha256sum`-format file naming the archive and every file in it |
| `url` | the extension in the author console, where the release waits for review |

## Licence

MIT, see [LICENSE](LICENSE).
