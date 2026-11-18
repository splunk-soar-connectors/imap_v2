# Testing IMAP ES polling

The connector requires published Splunk SOAR SDK 7.2.2 or later. The commands
below use the released version pinned in `uv.lock`.

```sh
uv run --frozen --python 3.13 pytest -q
uv run --frozen --python 3.13 soarapps package build . \
  --output-file dist/ar2061/imap_v2-ar2061.tgz
```

The cases in `tests/test_es_poll_sdk.py` run with the released SDK.
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
current batch, skips the failed email and continues to later messages. The
next scheduled poll must not replay processed messages. Timeouts during bounded
SDK retries can still create duplicates. Upload failures alone do not replay findings.

The connector stages its cursor before yielding each finding. Latest-first polls
also retain unprocessed UIDs so a checkpoint cannot skip older selected emails.

The attachment reference URI is temporary. SAA requires the companion `app-ess`
reader update. Browser download support and the race between finding creation
and asynchronous association persistence still need integration work. Begin
with automatic threat analysis and automation disabled; enable them only when
testing that readiness behavior. A `queued` association result confirms enqueueing,
not completed persistence. Local tests do not establish live ES, S3 or Timeline
readiness.

Individual failed emails are skipped with their ID and error category in warning
logs, without message contents or upstream error text. Skipped messages are not
automatically replayed, so data can be lost; this change adds no dead letter
queue. Source failures before a message can be identified still stop polling.

Connector-local log filters redact released SDK parser debug details and HTTPX
request URLs while retaining debug events and HTTP methods/statuses. SDK source
is unchanged. Regression tests exercise real parser logging and HTTPX request
logging with simulated secrets at DEBUG/INFO levels.
