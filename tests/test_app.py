# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from soar_sdk.extras.email.email_data import (
    EmailAttachment,
    EmailBody,
    EmailData,
    EmailHeaders,
)

from src import app as imap_app


def _asset(**overrides):
    values = {
        "auth_type": "Basic",
        "use_ssl": False,
        "server": "mail.example.com",
        "username": "user",
        "password": None,
        "folder": "INBOX",
        "verify_server_cert": True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_starttls_failure_prevents_login(mocker):
    connection = MagicMock()
    connection.starttls.side_effect = imap_app.imaplib.IMAP4.error("TLS not supported")
    mocker.patch.object(imap_app.imaplib, "IMAP4", return_value=connection)

    helper = imap_app.ImapHelper(MagicMock(), _asset())

    with pytest.raises(Exception, match="Error connecting to server"):
        helper._connect_to_server()

    connection.login.assert_not_called()


def test_ssl_connection_uses_validating_context(mocker):
    context = MagicMock()
    mocker.patch.object(imap_app, "_create_ssl_context", return_value=context)
    ssl_connection = mocker.patch.object(imap_app.imaplib, "IMAP4_SSL")
    connection = ssl_connection.return_value
    connection.login.return_value = ("OK", [])
    connection.list.return_value = ("OK", [])
    connection.select.return_value = ("OK", [])

    helper = imap_app.ImapHelper(MagicMock(), _asset(use_ssl=True))
    helper._connect_to_server()

    ssl_connection.assert_called_once_with("mail.example.com", ssl_context=context)


@pytest.mark.parametrize(
    "value",
    ["1\r\nA001 DELETE INBOX", "0", "-1", "\uff11\uff12"],
)
def test_invalid_email_id_is_rejected(value):
    with pytest.raises(ValueError, match="Email ID"):
        imap_app._validate_imap_uid(value)


def test_mailbox_name_is_quoted_and_line_breaks_are_rejected():
    assert imap_app._quote_mailbox('folder "name"') == '"folder \\"name\\""'

    with pytest.raises(ValueError, match="line breaks"):
        imap_app._quote_mailbox("INBOX\r\nA001 DELETE INBOX")


def test_get_email_is_not_read_only():
    assert imap_app.get_email.meta.read_only is False


def test_checkpoint_retries_failed_email_without_blocking_forever():
    checkpoint, retry_counts, exhausted = imap_app._next_email_checkpoint(
        [10, 11, 12], [11], {}
    )
    assert (checkpoint, retry_counts, exhausted) == (11, {"11": 1}, [])

    checkpoint, retry_counts, exhausted = imap_app._next_email_checkpoint(
        [11, 12, 13], [11], {"11": 1}
    )
    assert (checkpoint, retry_counts, exhausted) == (11, {"11": 2}, [])

    checkpoint, retry_counts, exhausted = imap_app._next_email_checkpoint(
        [11, 12, 13], [11], {"11": 2}
    )
    assert (checkpoint, retry_counts, exhausted) == (14, {}, [11])


def test_checkpoint_advances_after_success():
    assert imap_app._next_email_checkpoint([10, 11, 12], [], {}) == (13, {}, [])


@pytest.mark.parametrize("value", ["0", "-1", "1/artifacts", "\uff11"])
def test_invalid_container_id_is_rejected(value):
    with pytest.raises(ValueError, match="Container ID"):
        imap_app._validate_soar_id(value)


def test_forwarded_finding_preserves_outer_evidence():
    outer = EmailData(
        raw_email="From: reporter@example.com\r\n\r\nouter",
        headers=EmailHeaders(from_address="reporter@example.com"),
        body=EmailBody(plain_text="outer"),
        urls=["https://outer.example/phish"],
        attachments=[
            EmailAttachment(
                filename="payload.bin",
                content_type="application/octet-stream",
                content=b"payload",
            )
        ],
    )
    inner = EmailData(
        raw_email="From: sender@example.com\r\n\r\ninner",
        headers=EmailHeaders(from_address="sender@example.com"),
        body=EmailBody(plain_text="inner"),
        urls=["https://inner.example/message"],
    )

    finding = imap_app._build_forwarded_finding(
        "42",
        outer.raw_email,
        inner.raw_email.encode(),
        "forwarded.eml",
        outer,
        inner,
    )

    assert finding.email.urls == [
        "https://inner.example/message",
        "https://outer.example/phish",
    ]
    assert {attachment.file_name for attachment in finding.attachments} == {
        "forwarded.eml",
        "email_42.eml",
        "payload.bin",
    }


def test_inline_rfc822_part_does_not_reclassify_outer_email():
    outer = EmailData(
        raw_email="",
        headers=EmailHeaders(from_address="sender@example.com"),
        body=EmailBody(plain_text="outer"),
    )
    raw_email = """MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=BOUNDARY

--BOUNDARY
Content-Type: message/rfc822

From: decoy@example.com
Subject: Decoy

benign
--BOUNDARY--
"""

    assert imap_app._find_forwarded_attachment(outer, raw_email) is None


def test_build_vault_artifact_adds_hashes(tmp_path):
    attachment = tmp_path / "payload.bin"
    attachment.write_bytes(b"payload")
    vault = MagicMock()
    vault.add_attachment.return_value = "vault-id"
    vault.get_attachment.return_value = [
        {
            "metadata": {
                "sha256": "sha256-value",
                "sha1": "sha1-value",
                "md5": "md5-value",
            }
        }
    ]

    artifact = imap_app._build_vault_artifact(
        vault,
        {"file_name": "payload.bin", "file_path": str(attachment)},
        123,
    )

    vault.add_attachment.assert_called_once_with(
        container_id=123,
        file_location=str(attachment),
        file_name="payload.bin",
        metadata={},
    )
    assert artifact.cef["vaultId"] == "vault-id"
    assert artifact.cef["fileHashSha256"] == "sha256-value"
