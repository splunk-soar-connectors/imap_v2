# Testing IMAP with the SDK under review

Use a local SDK wheel to build and test IMAP before the SDK PRs merge. The
`feature/AR-2061-es-finding-api` SDK checkout must include the AR-2060 attachment
APIs, AR-2063 uploads, and AR-2061 finding and polling changes. The commands below
run from `imap_v2`, with `splunk-soar-sdk` in the neighbouring directory.

## Build and test

Rebuild the wheel whenever the SDK source changes:

```sh
(cd ../splunk-soar-sdk && uv build --wheel --out-dir ../imap_v2/dist/ar2061/sdk)
SDK_WHEEL="$PWD/dist/ar2061/sdk/splunk_soar_sdk-7.1.3-py3-none-any.whl"

uv run --frozen --python 3.13 --refresh-package splunk-soar-sdk \
  --with "$SDK_WHEEL" pytest -q

uv run --frozen --python 3.13 --refresh-package splunk-soar-sdk \
  --with "$SDK_WHEEL" soarapps package build . \
  --with-sdk-wheel-from "$SDK_WHEEL" \
  --output-file dist/ar2061/imap_v2-ar2061.tgz
```

Adjust the wheel filename if the SDK version changes. Both the packaging CLI and
the packaged app use the wheel supplied above. The app's published dependency
requirements and `uv.lock` remain unchanged. The wheel uses the source checkout's
version number; this is a development build, not the published SDK release with
that number. The resulting TGZ can be shared directly for testing, including
changes that have not yet been pushed to the SDK branch.

The cases in `tests/test_es_poll_sdk.py` must pass with the preview wheel.
They skip when using a released SDK that lacks the new execution-context hook.
They exercise the real IMAP polling handler, email parsing, SDK finding
serialization and result handling. IMAP, upload transport, ES HTTP responses and
the bundle attachment bridge are simulated. Checks cover empty polls, bounded
batches, correct finding-to-attachment ownership, partial failures, cleanup and
secret-free results.

For Python 3.15, use a compatible test runner in a separate environment. This
keeps the app's existing pytest 7 development constraint and lock unchanged:

```sh
UV_PROJECT_ENVIRONMENT=/tmp/imap-sdk-python315 \
  uv run --frozen --python 3.15 --no-dev \
  --refresh-package splunk-soar-sdk --with "$SDK_WHEEL" \
  --with 'pytest>=9,<10' --with pytest-mock pytest -q
```

## Test in an ingestion environment

Install `dist/ar2061/imap_v2-ar2061.tgz` through the normal connector installation
flow. The runtime bundle must also contain the matching `attachment_api` and
`es_poll_api` bridges from the companion `soar-services` changes. The orchestrator
must provide a routable ES base URL and execution token. The token belongs in
runtime execution context, never in connector asset settings.

Use a test mailbox with plain emails, ordinary attachments and forwarded `.eml`
messages. Invoke semantic `on_es_poll`, then inspect the action result's finding
IDs and attachment upload/link outcomes. Confirm each finding references its own
uploaded files and that Timeline eventually stores its associations. Include a
finding failure and an upload failure. A finding creation failure finishes the
current batch and stops polling; the next scheduled poll replays that batch.
Previously checkpointed batches must not repeat. Successful findings within a
failed batch can be duplicated. Upload failures alone do not replay findings.

The connector stages its cursor before yielding each finding. Latest-first polls
also retain unprocessed UIDs so a checkpoint cannot skip older selected emails.

The attachment reference URI is temporary. SAA requires the companion `app-ess`
reader update. Browser download support and the race between finding creation
and asynchronous association persistence still need integration work. Begin
with automatic threat analysis and automation disabled; enable them only when
testing that readiness behavior. A `queued` association result confirms enqueueing,
not completed persistence. Local tests do not establish live ES, S3 or Timeline
readiness.
