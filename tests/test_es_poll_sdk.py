# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

"""Exercise IMAP's real polling handler with the SDK under review."""

import json
import sys
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest
from soar_sdk.asset_state import AssetState
from soar_sdk.params import OnESPollParams

from src import app as imap_app

pytestmark = pytest.mark.skipif(
    not hasattr(imap_app.app.soar_client, "_get_es_finding_context"),
    reason="Run with the AR-2061 SDK wheel; see TESTING_ES_POLL.md.",
)

if hasattr(imap_app.app.soar_client, "_get_es_finding_context"):
    from soar_sdk.exceptions import AttachmentUploadError
    from soar_sdk.models.attachment_upload import AttachmentUploadResult

ES_URL = "https://es.example:8089"
ES_TOKEN = "test-es-token-never-exposed"
FILE_CONTENT = b"test-file-content-never-exposed"


@pytest.fixture
def poll_runtime(monkeypatch, mocker):
    app = imap_app.app
    asset = imap_app.Asset(server="imap.example", username="test-user")
    state = {}
    mocker.patch.object(app.actions_manager, "load_state", side_effect=state.copy)
    mocker.patch.object(app.actions_manager, "save_state", side_effect=state.update)
    asset._ingest_state = AssetState(
        app.actions_manager, "ingest", "1", encrypted=False
    )
    monkeypatch.setattr(app, "_asset", asset, raising=False)
    monkeypatch.setattr(app, "_es_ingest_config", {"es_security_domain": "threat"})
    mocker.patch.object(app.actions_manager, "add_result")
    mocker.patch.object(
        app.actions_manager,
        "save_container",
        side_effect=AssertionError("SOAR container call"),
    )
    mocker.patch.object(
        app.soar_client, "get", side_effect=AssertionError("SOAR REST call")
    )
    mocker.patch.object(
        app.soar_client, "post", side_effect=AssertionError("SOAR REST call")
    )
    monkeypatch.setitem(
        sys.modules,
        "es_poll_api",
        SimpleNamespace(
            get_es_context=lambda: (ES_URL, ES_TOKEN),
            get_attachment_reference_base_url=lambda: ES_URL + "/attachment-proxy",
        ),
    )
    context = SimpleNamespace(
        state=state,
        ids=[],
        paths=[],
        events=[],
        payloads=[],
        reject_upload=None,
        reject_finding=None,
        reservation_fails=False,
    )

    def reserve(names, key):
        UUID(key)
        context.events.append("reserve")
        if context.reservation_fails:
            raise RuntimeError(ES_TOKEN)
        targets = []
        for name in names:
            identifier = str(UUID(int=len(context.ids) + 1))
            context.ids.append(identifier)
            targets.append(
                {
                    "attachment_id": identifier,
                    "file_name": name,
                    "upload_url": "https://uploads.example/?signature=test-signed-secret",
                    "form_fields": [{"name": "key", "value": "test-form-secret"}],
                    "expires_at": datetime.now(UTC) + timedelta(minutes=5),
                    "max_size_bytes": 1024 * 1024,
                }
            )
        return targets

    def upload(path, target, **_kwargs):
        context.paths.append(path)
        context.events.append("upload")
        assert path.is_file()
        if target.attachment_id == context.reject_upload:
            raise AttachmentUploadError(
                "Upload failed.", "unavailable", target.attachment_id, 503
            )
        if target.file_name == "note.txt":
            assert path.read_bytes() == FILE_CONTENT
        return AttachmentUploadResult(
            attachment_id=target.attachment_id,
            file_name=target.file_name,
            size_bytes=path.stat().st_size,
        )

    bridge = SimpleNamespace(
        get_upload_targets=mocker.Mock(side_effect=reserve),
        associate_subject_attachments=mocker.Mock(return_value="queued-message"),
    )
    monkeypatch.setitem(sys.modules, "attachment_api", bridge)
    # The SDK client caches its bridge; isolate that cache between test runs.
    monkeypatch.setattr(app.soar_client.attachments, "_bridge", None)
    mocker.patch.object(app.soar_client.attachments, "upload_file", side_effect=upload)
    context.bridge = bridge
    helper = mocker.patch.object(imap_app, "ImapHelper").return_value
    helper._get_email_data.side_effect = lambda uid: (email_message(uid), None)
    context.helper = helper

    def create(_client, url, *, content, headers):
        assert url == ES_URL + "/servicesNS/nobody/missioncontrol/public/v2/findings"
        assert headers["Authorization"] == "Bearer " + ES_TOKEN
        payload = json.loads(content)
        assert context.events.count("upload") == len(context.ids)
        context.events.append("create")
        context.payloads.append(payload)
        index = len(context.payloads)
        if index == context.reject_finding:
            return httpx.Response(503, text=ES_TOKEN)
        return httpx.Response(
            201, json={"_time": "now", "finding_id": f"finding-{index}"}
        )

    mocker.patch.object(httpx.Client, "post", autospec=True, side_effect=create)
    return context


def email_message(uid):
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.com"
    message["Subject"] = f"Reported mail {uid}"
    message.set_content("Reported email for investigation")
    message.add_attachment(
        FILE_CONTENT, maintype="text", subtype="plain", filename="note.txt"
    )
    return message.as_string()


def result():
    return imap_app.app.actions_manager.add_result.call_args.args[0]


@pytest.mark.parametrize("count", [0, 1, 3, 11])
def test_imap_poll_uses_sdk_for_ordered_upload_create_and_link(
    poll_runtime, count, caplog
):
    context = poll_runtime
    context.helper._get_email_ids_to_process.return_value = (
        list(range(1, count + 1)),
        [],
    )

    assert imap_app.on_es_poll(OnESPollParams())

    summary = result().get_summary()
    assert summary["status"] == "success"
    assert summary["created"] == count
    assert summary["attachments_uploaded"] == count * 2
    assert summary["links_queued"] == count * 2
    assert len(context.ids) == len(set(context.ids)) == count * 2
    batches = [min(20, count * 2 - start) for start in range(0, count * 2, 20)]
    assert [
        len(call.args[0]) for call in context.bridge.get_upload_targets.call_args_list
    ] == batches
    associations = [
        item
        for call in context.bridge.associate_subject_attachments.call_args_list
        for item in call.args[0]
    ]
    assert associations == [
        {
            "subject_id": f"finding-{index + 1}",
            "attachment_ids": context.ids[index * 2 : index * 2 + 2],
        }
        for index in range(count)
    ]
    for index, payload in enumerate(context.payloads):
        email = payload["email"]
        assert email["raw_email_link"].endswith(
            "attachment_id=" + context.ids[index * 2]
        )
        assert [entry["filename"] for entry in email["attachments"]] == [
            f"email_{index + 1}.eml",
            "note.txt",
        ]
    assert all(not path.exists() for path in context.paths)
    if count:
        assert context.state["ingest"]["es_next_muid"] == count + 1
    assert_secret_free(caplog.text)


@pytest.mark.parametrize("reservation_fails", [False, True])
def test_imap_poll_reports_partial_failures_without_linking_failed_inputs(
    poll_runtime, reservation_fails, caplog
):
    context = poll_runtime
    context.helper._get_email_ids_to_process.return_value = ([1, 2, 3], [])
    context.reservation_fails = reservation_fails
    context.reject_upload = str(UUID(int=2))
    context.reject_finding = 2

    assert imap_app.on_es_poll(OnESPollParams())

    summary = result().get_summary()
    assert summary["status"] == "partial"
    assert summary["created"] == 2
    assert summary["failed"] == 1
    assert summary["attachments_uploaded"] == (0 if reservation_fails else 5)
    assert summary["attachments_failed"] == (6 if reservation_fails else 1)
    assert summary["links_queued"] == (0 if reservation_fails else 3)
    if reservation_fails:
        context.bridge.associate_subject_attachments.assert_not_called()
        assert all(
            "attachments" not in payload["email"] for payload in context.payloads
        )
    else:
        context.bridge.associate_subject_attachments.assert_called_once_with(
            [
                {"subject_id": "finding-1", "attachment_ids": [context.ids[0]]},
                {"subject_id": "finding-3", "attachment_ids": context.ids[4:6]},
            ]
        )
        assert [
            entry["filename"] for entry in context.payloads[0]["email"]["attachments"]
        ] == ["email_1.eml"]
    assert context.state.get("ingest", {}).get("es_next_muid", 1) == 1
    assert all(not path.exists() for path in context.paths)
    assert_secret_free(caplog.text)


@pytest.mark.parametrize("manner", ["oldest first", "latest first"])
def test_failed_batch_replays_without_repeating_checkpointed_emails(
    poll_runtime, manner
):
    context = poll_runtime
    imap_app.app.asset.ingest_manner = manner
    context.helper._get_email_ids_to_process.side_effect = lambda limit, lower, order: (
        list(range(lower, 26)),
        [],
    )
    context.reject_finding = 12

    assert imap_app.on_es_poll(OnESPollParams())
    assert result().get_summary()["created"] == 19
    assert result().get_summary()["failed"] == 1
    first_batch = (
        list(range(1, 11)) if manner == "oldest first" else list(range(25, 15, -1))
    )
    failed_batch = (
        list(range(11, 21)) if manner == "oldest first" else list(range(15, 5, -1))
    )
    assert [p["rule_title"] for p in context.payloads] == [
        f"sender@example.com reported email - Reported mail {uid}"
        for uid in first_batch + failed_batch
    ]
    checkpoint = context.state["ingest"]
    assert checkpoint["es_next_muid"] == (11 if manner == "oldest first" else 26)
    if manner == "latest first":
        assert checkpoint["es_pending_email_uids"] == list(range(1, 16))

    context.reject_finding = None
    count = len(context.payloads)
    assert imap_app.on_es_poll(OnESPollParams())
    remaining = (
        list(range(11, 26)) if manner == "oldest first" else list(range(15, 0, -1))
    )
    assert [p["rule_title"] for p in context.payloads[count:]] == [
        f"sender@example.com reported email - Reported mail {uid}" for uid in remaining
    ]
    assert context.state["ingest"]["es_next_muid"] == 26
    assert not context.state["ingest"].get("es_pending_email_uids")


def test_checkpoint_preserves_unprocessed_email_retries(poll_runtime, monkeypatch):
    context = poll_runtime
    state = imap_app.app.asset.ingest_state
    state.put_all({"es_next_muid": 100, "es_failed_muid_retries": {"1": 1, "2": 1}})
    context.helper._get_email_ids_to_process.return_value = ([100], [])
    monkeypatch.setattr(imap_app.app.soar_client, "MAX_BULK_FINDINGS", 1)
    context.reject_finding = 2

    assert imap_app.on_es_poll(OnESPollParams())
    assert state["es_next_muid"] == 100
    assert state["es_failed_muid_retries"] == {"2": 1}


@pytest.mark.parametrize("attempts", [0, 2])
def test_processing_failure_is_counted_once_across_batch_checkpoints(
    poll_runtime,
    monkeypatch,
    attempts,
):
    context = poll_runtime
    state = imap_app.app.asset.ingest_state
    state.put_all({"es_failed_muid_retries": {"1": attempts}})
    context.helper._get_email_ids_to_process.return_value = ([1, 2, 3], [])

    def read(uid):
        if uid == 1:
            raise RuntimeError("Email unavailable")
        return email_message(uid), None

    context.helper._get_email_data.side_effect = read
    monkeypatch.setattr(imap_app.app.soar_client, "MAX_BULK_FINDINGS", 1)
    assert imap_app.on_es_poll(OnESPollParams())
    assert state["es_next_muid"] == 4
    assert state["es_failed_muid_retries"] == ({"1": 1} if attempts == 0 else {})


def test_manual_poll_does_not_advance_scheduled_checkpoint(poll_runtime):
    context = poll_runtime
    state = imap_app.app.asset.ingest_state
    original = {"es_next_muid": 100, "es_failed_muid_retries": {"1": 1}}
    state.put_all(original)
    context.helper._get_email_ids_to_process.return_value = ([100, 101], [])
    assert imap_app.on_es_poll(OnESPollParams(container_count=1))
    assert state.get_all() == original
    assert result().get_summary()["created"] == 1


def assert_secret_free(logs):
    rendered = repr(vars(result())) + logs
    for secret in (
        ES_TOKEN,
        FILE_CONTENT.decode(),
        "test-signed-secret",
        "test-form-secret",
    ):
        assert secret not in rendered
