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


def test_checkpoint_stops_at_first_failed_email():
    assert imap_app._next_email_checkpoint([10, 11, 12], [11]) == 11
    assert imap_app._next_email_checkpoint([10, 11, 12], []) == 13


@pytest.mark.parametrize("value", ["0", "-1", "1/artifacts", "\uff11"])
def test_invalid_container_id_is_rejected(value):
    with pytest.raises(ValueError, match="Container ID"):
        imap_app._validate_soar_id(value)
