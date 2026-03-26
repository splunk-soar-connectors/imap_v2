# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
import contextlib
import email
import hashlib
import imaplib
import json
import socket
import time
from collections.abc import Generator, Iterator
from datetime import datetime, UTC
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from pydantic import Field as PydanticField

from dateutil import tz
from imapclient import imap_utf7
from parse import parse
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.auth import AuthorizationCodeFlow
from soar_sdk.auth.client import (
    SOARAssetOAuthClient,
    AuthorizationRequiredError,
    TokenRefreshError,
)
from soar_sdk.auth.models import OAuthConfig
from soar_sdk.extras.email import EmailProcessor, ProcessEmailContext
from soar_sdk.extras.email.email_data import EmailData, extract_email_data
from soar_sdk.extras.email.utils import decode_uni_string
from soar_sdk.logging import getLogger
from soar_sdk.models.artifact import Artifact
from soar_sdk.models.container import Container
from soar_sdk.models.finding import (
    Finding,
    FindingAttachment,
    FindingEmail,
    FindingEmailReporter,
)
from soar_sdk.params import OnESPollParams, OnPollParams, Param, Params
from soar_sdk.shims.phantom.vault import PhantomVault
from soar_sdk.webhooks.models import WebhookRequest, WebhookResponse

from .imap_consts import (
    IMAP_CONNECTED_TO_SERVER,
    IMAP_ERROR_CONNECTING_TO_SERVER,
    IMAP_ERROR_CONNECTIVITY_TEST,
    IMAP_ERROR_LISTING_FOLDERS,
    IMAP_ERROR_LOGGING_IN_TO_SERVER,
    IMAP_ERROR_SELECTING_FOLDER,
    IMAP_FETCH_ID_FAILED,
    IMAP_FETCH_ID_FAILED_RESULT,
    IMAP_GENERAL_ERROR_MESSAGE,
    IMAP_GOT_LIST_FOLDERS,
    IMAP_LOGGED_IN,
    IMAP_SELECTED_FOLDER,
    IMAP_SUCCESS_CONNECTIVITY_TEST,
)

IMAP_APP_ID = "69a0cc22-227b-4ecf-bf9d-443cabe870a0"

logger = getLogger()

_EML_CONTENT_TYPES = {"message/rfc822"}


def _is_forwarded_email_attachment(filename: str, content_type: str | None) -> bool:
    lower = filename.lower()
    if lower.endswith((".eml", ".msg")):
        return True
    return content_type is not None and content_type.lower() in _EML_CONTENT_TYPES


def _parse_attached_email(content: bytes, email_id: str) -> EmailData | None:
    """Parse an attached .eml or .msg file into EmailData."""
    return extract_email_data(content, email_id, include_attachment_content=True)


def _extract_address(header_value: str | None) -> str | None:
    """Extract a single clean email address from a header value."""
    if not header_value:
        return None
    _, addr = parseaddr(header_value)
    return addr or None


def _extract_addresses(header_value: str | None) -> str | list[str] | None:
    """Extract email address(es) from a header value.

    Returns a single string for one address, a list for multiple, or None.
    """
    if not header_value:
        return None
    pairs = getaddresses([header_value])
    addrs = [addr for _, addr in pairs if addr]
    if not addrs:
        return None
    if len(addrs) == 1:
        return addrs[0]
    return addrs


def _build_reporter(outer: EmailData, email_id: str) -> FindingEmailReporter | None:
    """Build a FindingEmailReporter from the outer/wrapper email."""
    from_addr = _extract_address(outer.headers.from_address)
    if not from_addr:
        return None

    data: dict = {"from": from_addr}

    to = _extract_addresses(outer.headers.to)
    if to:
        data["to"] = to
    cc = _extract_addresses(outer.headers.cc)
    if cc:
        data["cc"] = cc
    bcc = _extract_addresses(outer.headers.bcc)
    if bcc:
        data["bcc"] = bcc
    if outer.headers.subject:
        data["subject"] = outer.headers.subject
    if outer.headers.message_id:
        data["message_id"] = outer.headers.message_id
    data["id"] = str(email_id)

    outer_body = outer.body.plain_text or outer.body.html or ""
    if outer_body:
        data["body"] = outer_body

    if outer.headers.date:
        data["date"] = outer.headers.date

    return FindingEmailReporter(**data)


def _find_forwarded_attachment(
    outer_data: EmailData, raw_email: str
) -> tuple[bytes, str] | None:
    """Find a forwarded .eml/.msg attachment in the email.

    Checks both parsed attachments and raw MIME parts (for message/rfc822
    parts that the SDK parser does not extract as attachments).
    """
    for att in outer_data.attachments:
        if att.content and _is_forwarded_email_attachment(
            att.filename, att.content_type
        ):
            return att.content, att.filename

    # The SDK skips message/rfc822 MIME parts during attachment extraction,
    # so scan the raw message directly for embedded email parts.
    mail = email.message_from_string(raw_email)
    for part in mail.walk():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                inner_msg = payload[0]
                inner_bytes = inner_msg.as_bytes()
                filename = part.get_filename() or "forwarded.eml"
                return inner_bytes, filename
    return None


def _build_finding_from_email(
    email_id: str, raw_email: str, outer_data: EmailData
) -> Finding:
    """Build a Finding from an email, detecting forwarded-as-attachment phishing reports."""
    forwarded = _find_forwarded_attachment(outer_data, raw_email)

    if forwarded:
        content, filename = forwarded
        inner_data = _parse_attached_email(content, email_id)
        if inner_data:
            return _build_forwarded_finding(
                email_id, content, filename, outer_data, inner_data
            )
        logger.warning(
            "Failed to parse forwarded attachment %s, treating as normal email",
            filename,
        )

    return _build_direct_finding(email_id, raw_email, outer_data)


def _format_utc_date(date_str: str | None) -> str:
    """Parse an email date header and return a UTC formatted string."""
    if not date_str:
        return "unknown date"
    try:
        dt = parsedate_to_datetime(date_str).astimezone(UTC)
        return dt.strftime("(%Y-%m-%d %H:%M UTC)")
    except Exception:
        return date_str


def _build_forwarded_title(outer_data: EmailData, inner_data: EmailData) -> str:
    """Build the rule_title for a forwarded-as-attachment (.eml/.msg) finding."""
    reporter = _extract_address(outer_data.headers.from_address) or "Unknown sender"
    original_sender = (
        _extract_address(inner_data.headers.from_address) or "Unknown sender"
    )
    subject = inner_data.headers.subject

    if subject:
        title = f"{reporter} reported email from {original_sender} - {subject}"
    else:
        date_str = _format_utc_date(inner_data.headers.date)
        title = (
            f"{reporter} reported email from {original_sender} - No subject {date_str}"
        )

    return title[:200]


def _build_forwarded_finding(
    email_id: str,
    inner_raw: bytes,
    inner_filename: str,
    outer_data: EmailData,
    inner_data: EmailData,
) -> Finding:
    """Build a Finding where the reported/inner email is the target and the outer is the reporter."""
    body_text = inner_data.body.plain_text or inner_data.body.html or ""
    email_headers = {k: v for k, v in inner_data.to_dict()["headers"].items() if v}

    attachments: list[FindingAttachment] = [
        FindingAttachment(
            file_name=inner_filename,
            data=inner_raw,
            is_raw_email=True,
        )
    ]
    for att in inner_data.attachments:
        if att.content:
            attachments.append(
                FindingAttachment(
                    file_name=att.filename,
                    data=att.content,
                    is_raw_email=False,
                )
            )

    return Finding(
        rule_title=_build_forwarded_title(outer_data, inner_data),
        email=FindingEmail(
            headers=email_headers or None,
            body=body_text or None,
            urls=inner_data.urls or None,
            reporter=_build_reporter(outer_data, email_id),
        ),
        attachments=attachments,
    )


def _build_direct_title(email_data: EmailData) -> str:
    """Build the rule_title for a direct (non-attachment-forwarded) finding."""
    sender = _extract_address(email_data.headers.from_address) or "Unknown sender"
    subject = email_data.headers.subject

    if subject:
        title = f"{sender} reported email - {subject}"
    else:
        date_str = _format_utc_date(email_data.headers.date)
        title = f"{sender} reported email - No subject {date_str}"

    return title[:200]


def _build_direct_finding(
    email_id: str, raw_email: str, email_data: EmailData
) -> Finding:
    """Build a Finding from a regular (non-forwarded) email."""
    body_text = email_data.body.plain_text or email_data.body.html or ""
    email_headers = {k: v for k, v in email_data.to_dict()["headers"].items() if v}

    raw_eml = raw_email.encode("utf-8") if isinstance(raw_email, str) else raw_email
    attachments: list[FindingAttachment] = [
        FindingAttachment(
            file_name=f"email_{email_id}.eml",
            data=raw_eml,
            is_raw_email=True,
        )
    ]
    for att in email_data.attachments:
        if att.content:
            attachments.append(
                FindingAttachment(
                    file_name=att.filename,
                    data=att.content,
                    is_raw_email=False,
                )
            )

    return Finding(
        rule_title=_build_direct_title(email_data),
        email=FindingEmail(
            headers=email_headers or None,
            body=body_text or None,
            urls=email_data.urls or None,
        ),
        attachments=attachments,
    )


class Asset(BaseAsset):
    # Connectivity fields
    server: str = AssetField(
        required=True,
        description="Server IP/Hostname",
        category=FieldCategory.CONNECTIVITY,
    )
    auth_type: str = AssetField(
        required=False,
        description="Authentication Mechanism to Use",
        default="Basic",
        value_list=["Basic", "OAuth"],
        category=FieldCategory.CONNECTIVITY,
    )
    username: str = AssetField(
        required=True, description="Username", category=FieldCategory.CONNECTIVITY
    )
    password: str = AssetField(
        required=False,
        description="Password",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    client_id: str = AssetField(
        required=False,
        description="OAuth Client ID",
        category=FieldCategory.CONNECTIVITY,
    )
    client_secret: str = AssetField(
        required=False,
        description="OAuth Client Secret",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    auth_url: str = AssetField(
        required=False,
        description="OAuth Authorization URL",
        default="https://accounts.google.com/o/oauth2/auth",
        category=FieldCategory.CONNECTIVITY,
    )
    token_url: str = AssetField(
        required=False,
        description="OAuth Token URL",
        default="https://oauth2.googleapis.com/token",
        category=FieldCategory.CONNECTIVITY,
    )
    scopes: str = AssetField(
        required=False,
        description="OAuth API Scope (JSON formatted list)",
        default='["https://mail.google.com/"]',
        category=FieldCategory.CONNECTIVITY,
    )
    use_ssl: bool = AssetField(
        required=False,
        description="Use SSL",
        default=False,
        category=FieldCategory.CONNECTIVITY,
    )

    # Ingestion fields
    folder: str = AssetField(
        required=True,
        description="Folder to ingest mails from (default is inbox)",
        default="inbox",
        category=FieldCategory.INGEST,
    )
    ingest_manner: str = AssetField(
        required=True,
        description="How to ingest",
        default="oldest first",
        value_list=["oldest first", "latest first"],
        category=FieldCategory.INGEST,
    )
    first_run_max_emails: int = AssetField(
        required=True,
        description="Maximum emails to poll first time for schedule and interval polling",
        default=2000,
        category=FieldCategory.INGEST,
    )
    max_emails: int = AssetField(
        required=True,
        description="Maximum emails to poll",
        default=100,
        category=FieldCategory.INGEST,
    )
    extract_attachments: bool = AssetField(
        required=False,
        description="Extract Attachments",
        default=True,
        category=FieldCategory.INGEST,
    )
    extract_urls: bool = AssetField(
        required=False,
        description="Extract URLs",
        default=True,
        category=FieldCategory.INGEST,
    )
    extract_ips: bool = AssetField(
        required=False,
        description="Extract IPs",
        default=True,
        category=FieldCategory.INGEST,
    )
    extract_domains: bool = AssetField(
        required=False,
        description="Extract Domain Names",
        default=True,
        category=FieldCategory.INGEST,
    )
    extract_hashes: bool = AssetField(
        required=False,
        description="Extract Hashes",
        default=True,
        category=FieldCategory.INGEST,
    )
    add_body_to_header_artifacts: bool = AssetField(
        required=False,
        description="Add email body to the Email Artifact",
        default=False,
        category=FieldCategory.INGEST,
    )


app = App(
    name="IMAP v2",
    app_type="email",
    logo="logo_splunk.svg",
    logo_dark="logo_splunk_dark.svg",
    product_vendor="Generic",
    product_name="IMAP v2",
    publisher="Splunk",
    appid="69a0cc22-227b-4ecf-bf9d-443cabe870a0",
    fips_compliant=True,
    asset_cls=Asset,
).enable_webhooks(default_requires_auth=False)


@app.webhook("result")
def handle_oauth_result(request: WebhookRequest[Asset]) -> WebhookResponse:
    query_params = {k: v[0] if v else "" for k, v in request.query.items()}

    if "error" in query_params:
        reason = query_params.get("error_description", "Unknown error")
        return WebhookResponse.text_response(
            content=f"Authorization failed: {reason}",
            status_code=400,
        )

    code = query_params.get("code")
    if not code:
        return WebhookResponse.text_response(
            content="Missing authorization code",
            status_code=400,
        )

    scopes = request.asset.scopes
    if isinstance(scopes, str):
        try:
            scopes = json.loads(scopes)
        except json.JSONDecodeError:
            scopes = [scopes]

    oauth_client = SOARAssetOAuthClient(
        OAuthConfig(
            client_id=request.asset.client_id,
            client_secret=request.asset.client_secret,
            authorization_endpoint=request.asset.auth_url,
            token_endpoint=request.asset.token_url,
            scope=scopes,
        ),
        request.asset.auth_state,
    )
    oauth_client.set_authorization_code(code)

    return WebhookResponse.text_response(
        content="Authorization successful! You can close this window.",
        status_code=200,
    )


class ImapHelper:
    """Helper class to manage IMAP connections and operations"""

    def __init__(self, soar: SOARClient, asset: Asset):
        self.soar = soar
        self.asset = asset
        self._imap_conn = None
        self._oauth_client = None
        self._folder_name = None
        self._is_hex = False

    def _generate_oauth_string(self, username, access_token):
        """Generates an IMAP OAuth2 authentication string"""
        auth_string = f"user={username}\1auth=Bearer {access_token}\1\1"
        return auth_string

    def _get_oauth_client(self) -> SOARAssetOAuthClient:
        """Get or create the OAuth client using SDK authentication."""
        if self._oauth_client is not None:
            return self._oauth_client

        # Force reload to pick up tokens stored by a different context (webhook/flow).
        # Workaround for SDK _load_state() not using force_reload.
        self.asset.auth_state.get_all(force_reload=True)

        scopes = self.asset.scopes
        if isinstance(scopes, str):
            try:
                scopes = json.loads(scopes)
            except json.JSONDecodeError:
                scopes = [scopes]

        config = OAuthConfig(
            client_id=self.asset.client_id,
            client_secret=self.asset.client_secret,
            authorization_endpoint=self.asset.auth_url,
            token_endpoint=self.asset.token_url,
            scope=scopes,
        )

        self._oauth_client = SOARAssetOAuthClient(
            config=config,
            auth_state=self.asset.auth_state,
        )
        return self._oauth_client

    def _get_oauth_access_token(self) -> str:
        """Get a valid OAuth access token, refreshing if necessary."""
        oauth_client = self._get_oauth_client()
        try:
            token = oauth_client.get_valid_token(auto_refresh=True)
            return token.access_token
        except AuthorizationRequiredError:
            raise Exception(
                "OAuth authorization required. Please complete the OAuth flow "
                "in the asset configuration."
            ) from None
        except TokenRefreshError as e:
            raise Exception(f"OAuth token refresh failed: {e}") from None

    def _connect_to_server(self, first_try=True, access_token=None):
        """Connect to the IMAP server"""
        is_oauth = self.asset.auth_type == "OAuth"
        use_ssl = self.asset.use_ssl
        server = self.asset.server

        socket.setdefaulttimeout(60)

        try:
            if is_oauth or use_ssl:
                self._imap_conn = imaplib.IMAP4_SSL(server)
            else:
                self._imap_conn = imaplib.IMAP4(server)
                with contextlib.suppress(Exception):
                    self._imap_conn.starttls()
        except Exception as e:
            raise Exception(
                IMAP_GENERAL_ERROR_MESSAGE.format(IMAP_ERROR_CONNECTING_TO_SERVER, e)
            ) from None

        logger.info(IMAP_CONNECTED_TO_SERVER)

        try:
            if is_oauth:
                if access_token is None:
                    access_token = self._get_oauth_access_token()
                auth_string = self._generate_oauth_string(
                    self.asset.username,
                    access_token,
                )
                result, _ = self._imap_conn.authenticate(
                    "XOAUTH2", lambda _: auth_string
                )
            else:
                result, _ = self._imap_conn.login(
                    self.asset.username, self.asset.password
                )
        except AuthorizationRequiredError:
            raise
        except Exception as e:
            if first_try and is_oauth and "Invalid credentials" in str(e):
                try:
                    oauth_client = self._get_oauth_client()
                    stored_token = oauth_client.get_stored_token()
                    if stored_token and stored_token.refresh_token:
                        oauth_client.refresh_token(stored_token.refresh_token)
                        return self._connect_to_server(False)
                except Exception as refresh_error:
                    logger.error(f"OAuth token refresh failed: {refresh_error}")
            raise Exception(
                IMAP_GENERAL_ERROR_MESSAGE.format(IMAP_ERROR_LOGGING_IN_TO_SERVER, e)
            ) from None

        if result != "OK":
            raise Exception(IMAP_ERROR_LOGGING_IN_TO_SERVER)

        logger.info(IMAP_LOGGED_IN)

        try:
            result, _ = self._imap_conn.list()
        except Exception as e:
            raise Exception(
                IMAP_GENERAL_ERROR_MESSAGE.format(IMAP_ERROR_LISTING_FOLDERS, e)
            ) from e

        logger.info(IMAP_GOT_LIST_FOLDERS)

        self._folder_name = self.asset.folder
        try:
            result, _ = self._imap_conn.select(
                f'"{imap_utf7.encode(self._folder_name).decode()}"', True
            )
        except Exception as e:
            raise Exception(
                IMAP_GENERAL_ERROR_MESSAGE.format(
                    IMAP_ERROR_SELECTING_FOLDER.format(folder=self._folder_name), e
                )
            ) from e

        if result != "OK":
            raise Exception(
                IMAP_ERROR_SELECTING_FOLDER.format(folder=self._folder_name)
            )

        logger.info(IMAP_SELECTED_FOLDER.format(folder=self._folder_name))

    def _get_email_data(self, muuid, folder=None, is_diff=False):
        """Get email data from IMAP server"""
        if is_diff and folder:
            try:
                result, data = self._imap_conn.select(
                    f'"{imap_utf7.encode(folder).decode()}"', True
                )
            except Exception as e:
                raise Exception(
                    IMAP_GENERAL_ERROR_MESSAGE.format(
                        IMAP_ERROR_SELECTING_FOLDER.format(folder=folder), e
                    )
                ) from e

            if result != "OK":
                raise Exception(IMAP_ERROR_SELECTING_FOLDER.format(folder=folder))

            logger.info(IMAP_SELECTED_FOLDER.format(folder=folder))

        try:
            (result, data) = self._imap_conn.uid(
                "fetch", muuid, "(INTERNALDATE RFC822)"
            )
        except TypeError:
            (result, data) = self._imap_conn.uid(
                "fetch", str(muuid), "(INTERNALDATE RFC822)"
            )
        except Exception as e:
            raise Exception(IMAP_FETCH_ID_FAILED.format(muuid=muuid, excep=e)) from e

        if result != "OK":
            raise Exception(
                IMAP_FETCH_ID_FAILED_RESULT.format(
                    muuid=muuid, result=result, data=data
                )
            )

        if not data or not isinstance(data, list):
            raise Exception(
                f"Invalid data returned for email ID {muuid}: data is not a list or is empty"
            )

        if data[0] is None:
            raise Exception(f"Email with ID {muuid} not found")

        if not isinstance(data[0], tuple) or len(data[0]) < 2:
            raise Exception(f"Invalid data structure for email ID {muuid}: {data[0]}")

        try:
            email_data = data[0][1].decode("UTF-8")
        except UnicodeDecodeError:
            email_data = data[0][1].decode("latin1")
        data_time_info = data[0][0].decode("UTF-8")

        return email_data, data_time_info

    def _get_email_ids_to_process(self, max_emails, lower_id, manner):
        """Get list of email UIDs to process based on ingestion manner"""
        try:
            result, data = self._imap_conn.uid("search", None, f"UID {lower_id!s}:*")
        except Exception as e:
            raise Exception(f"Failed to get email IDs: {e}") from e

        if result != "OK":
            raise Exception(f"Failed to get email IDs. Server response: {data}")

        if not data or not data[0]:
            return []

        uids = [int(uid) for uid in data[0].split()]

        if len(uids) == 1 and uids[0] < lower_id:
            return []

        uids.sort()
        max_emails = int(max_emails)

        if manner == "latest first":
            return uids[-max_emails:]
        else:
            return uids[:max_emails]

    def _parse_and_create_artifacts(
        self, email_id, email_data, data_time_info, asset, config=None
    ):
        """Parse email and yield Container and Artifacts for ingestion using SDK EmailProcessor"""
        epoch = int(time.mktime(datetime.now(tz=UTC).timetuple())) * 1000

        if data_time_info:
            parse_data = parse('{left_ignore}"{dt:tg}"{right_ignore}', data_time_info)

            if parse_data and "dt" in parse_data.named:
                dt = parse_data["dt"]
                dt.replace(tzinfo=tz.tzlocal())
                epoch = int(time.mktime(dt.timetuple())) * 1000

        if config is None:
            config = {
                "extract_attachments": asset.extract_attachments,
                "extract_domains": asset.extract_domains,
                "extract_hashes": asset.extract_hashes,
                "extract_ips": asset.extract_ips,
                "extract_urls": asset.extract_urls,
            }

        context = ProcessEmailContext(
            soar=self.soar,
            vault=PhantomVault(self.soar),
            app_id=IMAP_APP_ID,
            folder_name=self._folder_name,
            is_hex=self._is_hex,
            action_name=None,
            app_run_id=None,
        )
        email_processor = EmailProcessor(context, config)

        ret_val, message, results = email_processor._int_process_email(
            email_data, str(email_id), epoch
        )

        if not ret_val:
            logger.error(f"Failed to process email {email_id}: {message}")
            return

        for result in results:
            container_dict = result.get("container")
            if container_dict:
                yield Container(**container_dict)

            artifacts = result.get("artifacts", [])
            for artifact_dict in artifacts:
                if artifact_dict:
                    yield Artifact(**artifact_dict)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Test connectivity to IMAP server"""
    access_token = None
    if asset.auth_type == "OAuth":
        redirect_uri = app.get_webhook_url("result")
        logger.info(f"OAuth Redirect URI: {redirect_uri}")

        scopes = asset.scopes
        if isinstance(scopes, str):
            try:
                scopes = json.loads(scopes)
            except json.JSONDecodeError:
                scopes = [scopes]

        flow = AuthorizationCodeFlow(
            asset.auth_state,
            str(soar.get_asset_id()),
            client_id=asset.client_id,
            client_secret=asset.client_secret,
            authorization_endpoint=asset.auth_url,
            token_endpoint=asset.token_url,
            redirect_uri=redirect_uri,
            scope=scopes,
            extra_auth_params={
                "access_type": "offline",
                "prompt": "consent",
            },
        )

        auth_url = flow.get_authorization_url()
        logger.info(
            "Please connect to the following URL from a different tab "
            "to continue the connectivity process"
        )
        logger.info(auth_url)

        token = flow.wait_for_authorization()
        access_token = token.access_token

        # Re-persist the token. The SDK's fetch_token_with_authorization_code
        # overwrites the stored token with stale state when clearing the session.
        oauth_client = SOARAssetOAuthClient(
            OAuthConfig(
                client_id=asset.client_id,
                client_secret=asset.client_secret,
                authorization_endpoint=asset.auth_url,
                token_endpoint=asset.token_url,
                scope=scopes,
            ),
            asset.auth_state,
        )
        oauth_client._store_token(token)

        logger.info("OAuth authorization completed successfully")

    helper = ImapHelper(soar, asset)
    try:
        helper._connect_to_server(access_token=access_token)
        soar.set_message(IMAP_SUCCESS_CONNECTIVITY_TEST)
        logger.info(IMAP_SUCCESS_CONNECTIVITY_TEST)
    except Exception as e:
        error_msg = f"{IMAP_ERROR_CONNECTIVITY_TEST}: {e!s}"
        soar.set_message(error_msg)
        logger.error(error_msg)
        raise


@app.on_poll()
def on_poll(
    params: OnPollParams, soar: SOARClient, asset: Asset
) -> Iterator[Container | Artifact]:
    """Poll for new emails and ingest as containers/artifacts"""
    helper = ImapHelper(soar, asset)
    helper._connect_to_server()

    state = asset.ingest_state
    is_poll_now = params.is_manual_poll()

    if is_poll_now:
        lower_id = 1
        max_emails = (
            params.container_count if params.container_count > 0 else asset.max_emails
        )
    else:
        is_first_run = state.get("first_run", True)
        lower_id = state.get("next_muid", 1)
        max_emails = asset.first_run_max_emails if is_first_run else asset.max_emails

    email_ids = helper._get_email_ids_to_process(
        max_emails, lower_id, asset.ingest_manner
    )

    if not email_ids:
        logger.info("No new emails to ingest")
        return

    for email_id in email_ids:
        try:
            email_data, data_time_info = helper._get_email_data(email_id)

            yield from helper._parse_and_create_artifacts(
                email_id, email_data, data_time_info, asset
            )

        except Exception as e:
            logger.error(f"Error processing email {email_id}: {e}")
            continue

    if email_ids and not is_poll_now:
        state["next_muid"] = int(email_ids[-1]) + 1
        state["first_run"] = False


@app.on_es_poll()
def on_es_poll(
    params: OnESPollParams, soar: SOARClient, asset: Asset
) -> Generator[Finding, int | None]:
    """Poll for new emails and create ES findings for each email."""
    helper = ImapHelper(soar, asset)
    helper._connect_to_server()

    state = asset.ingest_state
    is_poll_now = params.is_manual_poll()
    lower_id = state.get("es_next_muid", 1)

    if is_poll_now:
        max_emails = (
            params.container_count if params.container_count > 0 else asset.max_emails
        )
    else:
        max_emails = asset.max_emails

    email_ids = helper._get_email_ids_to_process(
        max_emails, lower_id, asset.ingest_manner
    )

    if not email_ids:
        logger.info("No new emails to ingest for ES")
        return

    for email_id in email_ids:
        try:
            raw_email, _data_time_info = helper._get_email_data(email_id)
            outer_data = extract_email_data(
                raw_email, str(email_id), include_attachment_content=True
            )
        except Exception as e:
            logger.error(f"Error processing email {email_id} for ES: {e}")
            continue

        finding = _build_finding_from_email(str(email_id), raw_email, outer_data)

        state["es_next_muid"] = int(email_id) + 1

        yield finding


class GetEmailSummary(ActionOutput):
    """Summary output for get_email action"""

    container_id: int | None = None


class GetEmailParams(Params):
    id: str = Param(
        description="Message ID to get",
        required=False,
        primary=True,
        cef_types=["imap email id"],
        default="",
    )
    container_id: str = Param(
        description="Container ID to get email data from",
        required=False,
        primary=True,
        cef_types=["phantom container id"],
        default="",
    )
    folder: str = Param(
        description="Folder name of email to get(used when id is given as input)",
        required=False,
        default="",
    )
    ingest_email: bool = Param(
        description="Create container and artifacts", required=False, default=False
    )


class GetEmailOutput(ActionOutput):
    # Make all fields optional since not all emails have all headers
    message: str | None = None
    container_id: int | None = None
    ARC_Authentication_Results: str | None = PydanticField(
        None, alias="ARC-Authentication-Results"
    )
    ARC_Message_Signature: str | None = PydanticField(
        None, alias="ARC-Message-Signature"
    )
    ARC_Seal: str | None = PydanticField(None, alias="ARC-Seal")
    Accept_Language: str | None = PydanticField(
        None, example_values=["en-US"], alias="Accept-Language"
    )
    Authentication_Results: str | None = PydanticField(
        None, alias="Authentication-Results"
    )
    CC: str | None = PydanticField(None, example_values=["User <test@xyz.com>"])
    Content_Language: str | None = PydanticField(
        None, example_values=["en-US"], alias="Content-Language"
    )
    Content_Transfer_Encoding: str | None = PydanticField(
        None, example_values=["quoted-printable"], alias="Content-Transfer-Encoding"
    )
    Content_Type: str | None = PydanticField(
        None,
        example_values=[
            'multipart/alternative; boundary="00000000000082bcbd056d5b9c37"'
        ],
        alias="Content-Type",
    )
    DKIM_Signature: str | None = PydanticField(None, alias="DKIM-Signature")
    Date: str | None = PydanticField(
        None, example_values=["Tue, 29 May 2018 17:31:58 +0000"]
    )
    Delivered_To: str | None = PydanticField(
        None, example_values=["test.user@hello.com"], alias="Delivered-To"
    )
    FCC: str | None = PydanticField(None, example_values=["test://user@19.2.4.2/Sent"])
    Feedback_ID: str | None = PydanticField(None, alias="Feedback-ID")
    From: str | None = PydanticField(
        None, example_values=["The Test Team <test-noreply@hello.test.com>"]
    )
    In_Reply_To: str | None = PydanticField(None, alias="In-Reply-To")
    MIME_Version: str | None = PydanticField(
        None, example_values=["1.0"], alias="MIME-Version"
    )
    Message_ID: str | None = PydanticField(
        None,
        example_values=[
            "<88f9844d75d4b351.1527615118220.110312844.20155287.en.630c09e415f69497@test.com>"
        ],
        alias="Message-ID",
    )
    Received: str | None = PydanticField(None)
    Received_SPF: str | None = PydanticField(None, alias="Received-SPF")
    References: str | None = PydanticField(None)
    Reply_To: str | None = PydanticField(
        None,
        example_values=["The Test Team <test-noreply@hello.test.com>"],
        alias="Reply-To",
    )
    Return_Path: str | None = PydanticField(
        None, cef_types=["email"], alias="Return-Path"
    )
    Subject: str | None = PydanticField(None, example_values=["Test Email Subject"])
    Thread_Index: str | None = PydanticField(
        None, example_values=["AdZLNWgVDiTd5bCtTtyx3vkNcc0vtQ=="], alias="Thread-Index"
    )
    Thread_Topic: str | None = PydanticField(
        None, example_values=["beep for 4.9!"], alias="Thread-Topic"
    )
    To: str | None = PydanticField(None, example_values=["test.user@hello.com"])
    User_Agent: str | None = PydanticField(None, alias="User-Agent")
    X_Account_Key: str | None = PydanticField(
        None, example_values=["account7"], alias="X-Account-Key"
    )
    X_Gm_Message_State: str | None = PydanticField(None, alias="X-Gm-Message-State")
    X_Google_DKIM_Signature: str | None = PydanticField(
        None, alias="X-Google-DKIM-Signature"
    )
    X_Google_Id: str | None = PydanticField(
        None, example_values=["194824"], alias="X-Google-Id"
    )
    X_Google_Smtp_Source: str | None = PydanticField(None, alias="X-Google-Smtp-Source")
    X_Identity_Key: str | None = PydanticField(
        None, example_values=["id1"], alias="X-Identity-Key"
    )
    X_MS_Exchange_Organization_AuthAs: str | None = PydanticField(
        None, example_values=["Internal"], alias="X-MS-Exchange-Organization-AuthAs"
    )
    X_MS_Exchange_Organization_AuthMechanism: str | None = PydanticField(
        None, example_values=["04"], alias="X-MS-Exchange-Organization-AuthMechanism"
    )
    X_MS_Exchange_Organization_AuthSource: str | None = PydanticField(
        None,
        example_values=["test1.test.com"],
        alias="X-MS-Exchange-Organization-AuthSource",
    )
    X_MS_Exchange_Organization_SCL: str | None = PydanticField(
        None, example_values=["-1"], alias="X-MS-Exchange-Organization-SCL"
    )
    X_MS_Has_Attach: str | None = PydanticField(None, alias="X-MS-Has-Attach")
    X_MS_TNEF_Correlator: str | None = PydanticField(None, alias="X-MS-TNEF-Correlator")
    X_Mozilla_Draft_Info: str | None = PydanticField(None, alias="X-Mozilla-Draft-Info")
    X_Received: str | None = PydanticField(None, alias="X-Received")


@app.action(
    description="Get an email from the server or container",
    action_type="investigate",
    verbose='Every container that is created by the IMAP app has the following values:<ul><li>The container ID, that is generated by the Phantom platform.</li><li>The Source ID that the app equates to the email ID along with the hash of the folder name on the remote server</li><li>The raw_email data in the container\'s data field is set to the RFC822 format of the email.</li></ul>This action parses email data and if specified, creates containers and artifacts. The email data to parse is either extracted from the remote server if an email <b>id</b> is specified along with its folder name or from a Phantom container if the <b>contianer_id</b> is specified. The folder parameter is used only when the email id is specified in the input. If the folder is not mentioned, it takes the folder name from the asset configuration parameter. If the folder name is not specified as an input of the \\"get email\\" action or in asset configuration parameters, \\"inbox\\" is taken as its value.<br>If both parameters are specified, the action will use the <b>container_id</b>.<br>Do note that any containers and artifacts created will use the label configured in the asset.',
)
def get_email(params: GetEmailParams, soar: SOARClient, asset: Asset) -> GetEmailOutput:
    """Get an email from the server or container"""
    if not params.id and not params.container_id:
        raise ValueError("Please specify either id or container_id to get the email")

    helper = ImapHelper(soar, asset)

    if params.id:
        helper._connect_to_server()
        folder = params.folder if params.folder else asset.folder
        email_data, _data_time_info = helper._get_email_data(
            params.id, folder, is_diff=True
        )

        folder_encoded = folder.encode()
        folder_hash = hashlib.sha256(folder_encoded)
        folder_hex = folder_hash.hexdigest()

        helper._is_hex = True
        helper._folder_name = folder_hex

        mail = email.message_from_string(email_data)

        mail_header_dict = {}
        headers = mail.__dict__.get("_headers", [])
        for header in headers:
            try:
                mail_header_dict[header[0]] = str(make_header(decode_header(header[1])))
            except Exception:
                mail_header_dict[header[0]] = decode_uni_string(header[1], header[1])

        data_time_info = _data_time_info
        if data_time_info is None:
            header_date = mail_header_dict.get("Date")
            if header_date is not None:
                data_time_info = f'ignore_left "{header_date}" ignore_right'

        container_id = None
        if params.ingest_email:
            config = {
                "extract_attachments": True,
                "extract_domains": True,
                "extract_hashes": True,
                "extract_ips": True,
                "extract_urls": True,
            }

            containers_and_artifacts = list(
                helper._parse_and_create_artifacts(
                    params.id, email_data, data_time_info, asset, config=config
                )
            )

            for obj in containers_and_artifacts:
                if isinstance(obj, Container):
                    container_dict = obj.to_dict()
                    ret_val, message, cid = app.actions_manager.save_container(
                        container_dict
                    )
                    if ret_val:
                        container_id = cid
                    break

            if container_id:
                artifacts_to_save = []
                for obj in containers_and_artifacts:
                    if isinstance(obj, Artifact):
                        artifact_dict = obj.to_dict()
                        artifact_dict["container_id"] = container_id
                        artifacts_to_save.append(artifact_dict)
                if artifacts_to_save:
                    app.actions_manager.save_artifacts(artifacts_to_save)

            message = f"Email ingested with container ID: {container_id}"
            soar.set_summary(GetEmailSummary(container_id=container_id))
        else:
            message = "Email not ingested."

        soar.set_message(message)

        ret_val = {"message": message}
        if container_id:
            ret_val["container_id"] = container_id
        ret_val.update(mail_header_dict)

        return GetEmailOutput(**ret_val)

    if params.container_id:
        container = soar.get_container(params.container_id)
        if not container:
            raise ValueError(f"Container with ID {params.container_id} not found")

        soar.get_container_artifacts(params.container_id)

        ret_val = {}

        if container.get("data"):
            email_data = container["data"]
            if isinstance(email_data, dict):
                ret_val.update(email_data)

        return GetEmailOutput(**ret_val)

    raise ValueError("Please specify either id or container_id to get the email")


if __name__ == "__main__":
    app.cli()
