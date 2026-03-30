# IMAP v2

Publisher: Splunk <br>
Connector Version: 1.0.0 <br>
Product Vendor: Generic <br>
Product Name: IMAP v2 <br>
Minimum Product Version: 7.0.0

This app supports email ingestion and various investigative actions over IMAP

# IMAP v2

It is not uncommon for enterprises to have a single mailbox configured where users can forward
suspicious emails for further investigation. The ingestion feature in the IMAP v2 app is primarily
designed to pull emails from such a mailbox and create containers and artifacts in Splunk SOAR.

To add an IMAP v2 Asset in Splunk SOAR, from the **Main Menu** , select **Apps** . In the **Search Apps**
field, search for the **IMAP v2** App by typing "IMAP v2" into the search field and hitting enter. To the
right of the App name, click on the **Configure New Asset** button.

[![](img/imap_asset.png)](img/imap_asset.png)

In the **Asset Info** tab, the **Asset Name** and **Asset Description** can be whatever you want,
we've chosen "imap_ingest" for this example. The **Product Vendor** and **Product Name** fields will
be populated by Splunk SOAR and are not user-configurable. Do not click **Save** yet, navigate to the
**Ingest Settings** tab.

[![](img/imap_asset_ingest.png)](img/imap_asset_ingest.png)

The **Ingest Settings** tab sets the container type the ingested IMAP v2 data will be placed. Select
the appropriate label name or create a new label. In this example, the label name **imap** has been
selected. Choose "Off" for Manual polling from the dropdown of **Select a polling interval or
schedule to configure polling on this asset** or select "Scheduled" or "Interval". Set the **Polling
Interval** to the desired number of minutes. The settings in the **Approval Settings** and **Access
Control** tab are not used for the communication between Splunk SOAR and IMAP v2 and can be configured
later. Navigate to the **Asset Settings** tab if you are not already there.

[![](img/imap_asset_settings.png)](img/imap_asset_settings.png)

The **Asset Settings** tab provides the configuration information Splunk SOAR uses to communicate with
the mail server. Currently, there are two ways to authenticate.

- Basic
- OAuth

## Basic Authentication

Fill in the **Server IP/Hostname** , **Username** , and **Password** . The remaining configuration
fields can be adjusted to suit the email environment.
[![](img/imap_test_connectivity.png)](img/imap_test_connectivity.png)

## OAuth Authentication

Follow the steps outlined below to set up the OAuth application:

- Open the [Google API Console Credentials
  page](https://console.developers.google.com/apis/credentials) .
- Click **Select a project** , then **NEW PROJECT** , and enter a name for the project, and
  optionally, edit the provided project ID. Click **Create** .
  [![](img/imap_oauth_select_project.png)](img/imap_oauth_select_project.png)
- Select the created project from the top left corner, if not already selected.
- On the **Credentials** page, select **Create credentials** , then **OAuth client ID** .
- You may be prompted to set a product name on the Consent screen. If so, click **Configure
  consent screen** , supply the requested information, and click **Save** to return to the
  Credentials screen.
- Select **Web Application** for the **Application Type** . The **Redirect URLs** should be filled
  here. We will get **Redirect URLs** from the Splunk SOAR asset we create below in the section titled
  "Splunk SOAR asset for IMAP v2". You can keep it blank for now and Edit/Add it later.
- Click **Create** .
- On the page that appears, Note down the **client ID** and **client secret** somewhere secure, as
  you will need them while configuring the Splunk SOAR asset.

### Splunk SOAR Asset for IMAP v2

When creating an asset for the **IMAP v2** app, place the **client ID** and **client secret** in their
corresponding fields. Then, after filling in other values, click **SAVE** . Note that the password
field is optional for OAuth authentication. Keep the default values for the **OAuth Authorization
URL** , **OAuth Token URL** and **OAuth API Scope** parameters.

After saving, navigate to the **Webhook Settings** tab on the asset. Enable webhooks and copy the
**URL for this webhook** field. Append `/result` to the URL and place it in the **Redirect URIs**
field mentioned above. You can edit the client listed under **OAuth 2.0 Client IDs** on the
**Credentials** page to add a redirect url. After doing so, the URL should look something like
this:

https://\<soar_host>:3500/webhook/imapv2_69a0cc22-227b-4ecf-bf9d-443cabe870a0/\<asset_id>/result

Additionally, updating the Base URL in the Splunk SOAR Company Settings is also required. Navigate to
**Administration > Company Settings > Info** to configure the Base URL For Splunk SOAR.
Then, select **Save Changes** .

Once, the asset is configured follow the below steps to generate the access_token and refresh_token
pair.

- Hit the **TEST CONNECTIVITY** button under **Asset Settings**
- You will be asked to open a link in a new tab. Open the link in the same browser so that you are
  logged into Splunk SOAR for the redirect. If you wish to use a different browser, log in to
  Splunk SOAR first, and then open the provided link.
- Proceed to login to the Google site
- You will be prompted to agree to the permissions requested by the App
- If all goes well the browser should instruct you to close the tab
- Now go back and check the message on the Test Connectivity dialog box, it should say
  Connectivity test passed

**NOTE:**

- For the IMAP v2 app, we won't be able to route traffic through the proxy. So if the user tries to
  add any proxy in variables of the asset, it won't affect the app's connectivity. But the
  configured proxy variables will be used while generating tokens for the **OAuth authentication**
  .
- As of now, the OAuth authentication is supported for only Gmail mailbox.
- The parameter **Use SSL** will be ignored for the **OAuth authentication** , SSL mechanism will
  be used regardless of the parameter value.
- The IMAP v2 app uses webhooks for the OAuth flow. Webhooks must be enabled on the Splunk SOAR
  instance and also enabled for the IMAP v2 app specifically.

Now that the config is out of the way, let's delve into the two modes, in which ingestion can occur
and the differences between them.

## POLL NOW

Notice that you now have a **Poll Now** button, as shown here:
[![](img/imap_poll_now.png)](img/imap_poll_now.png)

Click **Poll Now** . There are a few options you can set, In this example the **Maximum containers**
to 1 and **Maximum artifacts** to 10, the default values are also fine. Click the **Poll Now**
button at the bottom of the dialog. You will see some text begin to scroll by inside the text field,
indicating progress. Parsing data might take a while. The dialog should look like this.

[![](img/imap_test_poll.png)](img/imap_test_poll.png)

One thing to note is that for every email that is ingested, a single container is created containing
multiple artifacts. The **Maximum artifacts** value will be ignored and all the possible artifacts
will be ingested into the container.

POLL NOW should be used to get a sense of the containers and artifacts that are created by the app.
The POLL NOW window allows the user to set the "Maximum containers" that should be ingested at this
instance. Since a single container is created for each email, this value equates to the maximum
emails that are ingested by the App. The App will either get the oldest email first or the latest,
depending upon the configuration parameter *How to ingest* .

## Scheduled Polling

This mode is used to schedule a polling action on the asset at regular intervals, which is
configured via the Ingest tab of the asset. It makes use of the following asset configuration
parameters (among others):

- Maximum emails to poll the first time

  The App detects the first time it is polling an asset and will ingest these number of emails (at
  the most).

- Maximum emails to poll

  For all scheduled polls after the first, the app will ingest these numbers of emails.

- How to ingest

  Should the app be ingesting the latest emails or the oldest?

In the case of Scheduled Polling, on every poll, the App remembers the last email that it has
ingested and will pick up from the next one in the next scheduled poll.

### How to ingest

The app allows the user to configure how it should ingest emails on every scheduled poll, *oldest
first* , or *latest first* . Depending upon the scheduled interval and how busy the inbox is one of
the following could potentially happen

- oldest first

  If the app is configured to poll too slowly and the inbox is so busy that on every poll the
  maximum ingested emails is less than the number of new emails, the app will never catch up.

- latest first

  If the app is configured to poll too slowly and the inbox is so busy that on every poll the
  maximum ingested emails is less than the number of new emails, the app will drop the older
  emails since it is ingesting the latest emails that came into the mailbox.

For best results, keep the poll interval and *Maximum emails to poll* values close to the number of
emails you would get within a time interval. This way, every poll will end up ingesting all the new
emails.

## Containers created

As mentioned before, the app will create a single container for each email that it ingests with the
following properties:

- Name

  The email subject is used as the name of the container. If a subject is not present the
  generated name is of the format: "Email UID: the_numeric_email_id"

- Source ID

  The source ID of the container will be set to the "{hash_value_of_foldername} : {email_id}".

The **data** section of the container will contain the complete raw email in a key named
'raw_email'. The UI allows the user to download this raw data JSON into a file. This same data can
be extracted in a playbook also for further processing.

## Artifacts created

The App will create the following type of artifacts:

- Email Artifact

  The email addresses that are found in the ingested email will be added as a separate artifact.
  Any attached email will also be scanned and the address present in the attached email will be
  added as a separate artifact. The emails are added as custom strings in the CEF structure in the
  following manner.

  | **Artifact Field** | **Value Details** |
  |--------------------|------------------------------------------------------------------------------------|
  | Source ID | Email ID set on the server |
  | cef.fromEmail | From email address |
  | cef.toEmail | To email address |
  | cef.emailHeaders | A dictionary containing each email header as a key and it's value as the key-value |

  [![](img/imap_email_artifact.png)](img/imap_email_artifact.png)

- IP Artifact

  - If **extract_ips** is enabled, any IPv4 or IPv6 found in the email body will be added, with
    one CEF per IP.
  - Any IP addresses found in the email are added to the CEF structure of an artifact.
  - The CEF for an IP is cef.sourceAddress.

- Hash Artifact - cef.fileHash

  - If **extract_hashes** is enabled, any hash found in the email body will be added, with one
    CEF per hash.
  - Any Hashes found in the email are added to the CEF structure of an artifact.
  - The CEF for a hash is cef.fileHash.

- URL Artifact - cef.requestURL

  - If **extract_urls** is enabled, any URL found in the email body will be added, with one CEF
    per URL.
  - Any URLs found are added to the CEF structure of an artifact.
  - The CEF for a URL is cef.requestURL.

- Domain Artifact - cef.destinationDnsDomain

  - If **extract_domains** is enabled, any domain found in the email body will be added, with
    one CEF per domain.
  - Domains that are part of a URL or an email address are added to the CEF structure of an
    artifact.
  - The CEF for a URL is cef.destinationDnsDomain.

- Vault Artifact

  - If the email contains any attachments, these are extracted (if enabled in the config) and
    added to the vault of the Container.
  - At the same time, the vault id and file name of this item is represented by a Vault
    Artifact.
  - The same file can be added to the vault multiple times. In this scenario, the file name of
    the item added the second time onwards will be slightly different, but the vault id will
    still be the same. However, there will be multiple artifacts created.
  - Do note that the system does *not* duplicate the file bytes, only the metadata in the db.
    | **Artifact Field** | **Value Details** |
    |--------------------|-------------------------------------|
    | Source ID | Email ID set on the server |
    | cef.vaultID | Vault ID of the attachment |
    | cef.fileName | Attached filename used in the email |
  - The legacy CEF fields **cs6** (value is the Vault ID) and **cs6Label** are deprecated.
    Use **cef.vaultID** instead in playbooks.
    [![](img/imap_vault_artifact.png)](img/imap_vault_artifact.png)

## Port Information

The app uses IMAP protocol for communicating with the email servers and HTTP/ HTTPS protocol for
obtaining/refreshing the access_token. Below are the default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |

Below are the ports used by IMAP library for the connection.

|         Service Name | Transport Protocol | Port |
|------------------------|--------------------|------|
|         Standard IMAP4 | tcp | 143 |
|         IMAP4-over-SSL | tcp | 993 |

### Configuration variables

This table lists the configuration variables required to operate IMAP v2. These variables are specified when configuring a IMAP v2 asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server** | required | string | Server IP/Hostname |
**auth_type** | optional | string | Authentication Mechanism to Use |
**username** | required | string | Username |
**password** | optional | password | Password |
**client_id** | optional | string | OAuth Client ID |
**client_secret** | optional | password | OAuth Client Secret |
**auth_url** | optional | string | OAuth Authorization URL |
**token_url** | optional | string | OAuth Token URL |
**scopes** | optional | string | OAuth API Scope (JSON formatted list) |
**use_ssl** | optional | boolean | Use SSL |
**folder** | required | string | Folder to ingest mails from (default is inbox) |
**ingest_manner** | required | string | How to ingest |
**first_run_max_emails** | required | numeric | Maximum emails to poll first time for schedule and interval polling |
**max_emails** | required | numeric | Maximum emails to poll |
**extract_attachments** | optional | boolean | Extract Attachments |
**extract_urls** | optional | boolean | Extract URLs |
**extract_ips** | optional | boolean | Extract IPs |
**extract_domains** | optional | boolean | Extract Domain Names |
**extract_hashes** | optional | boolean | Extract Hashes |
**add_body_to_header_artifacts** | optional | boolean | Add email body to the Email Artifact |

### Supported Actions

[test connectivity](#action-test-connectivity) - Test connectivity to IMAP server <br>
[on poll](#action-on-poll) - Poll for new emails and ingest as containers/artifacts <br>
[on es poll](#action-on-es-poll) - Poll for new emails and create ES findings for each email. <br>
[get email](#action-get-email) - Get an email from the server or container

## action: 'test connectivity'

Test connectivity to IMAP server

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

Poll for new emails and ingest as containers/artifacts

Type: **ingest** <br>
Read only: **True**

Callback action for the on_poll ingest functionality

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds). | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds). | numeric | |
**container_count** | optional | Maximum number of container records to query for. | numeric | |
**artifact_count** | optional | Maximum number of artifact records to query for. | numeric | |
**container_id** | optional | Comma-separated list of container IDs to limit the ingestion to. | string | |

#### Action Output

No Output

## action: 'on es poll'

Poll for new emails and create ES findings for each email.

Type: **ingest** <br>
Read only: **True**

Callback action for the on_es_poll ingest functionality

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds). | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds). | numeric | |
**container_count** | optional | Maximum number of findings to query for. | numeric | |

#### Action Output

No Output

## action: 'get email'

Get an email from the server or container

Type: **investigate** <br>
Read only: **True**

Every container that is created by the IMAP app has the following values:<ul><li>The container ID, that is generated by the Phantom platform.</li><li>The Source ID that the app equates to the email ID along with the hash of the folder name on the remote server</li><li>The raw_email data in the container's data field is set to the RFC822 format of the email.</li></ul>This action parses email data and if specified, creates containers and artifacts. The email data to parse is either extracted from the remote server if an email <b>id</b> is specified along with its folder name or from a Phantom container if the <b>contianer_id</b> is specified. The folder parameter is used only when the email id is specified in the input. If the folder is not mentioned, it takes the folder name from the asset configuration parameter. If the folder name is not specified as an input of the \\"get email\\" action or in asset configuration parameters, \\"inbox\\" is taken as its value.<br>If both parameters are specified, the action will use the <b>container_id</b>.<br>Do note that any containers and artifacts created will use the label configured in the asset.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** | optional | Message ID to get | string | `imap email id` |
**container_id** | optional | Container ID to get email data from | string | `phantom container id` |
**folder** | optional | Folder name of email to get(used when id is given as input) | string | |
**ingest_email** | optional | Create container and artifacts | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.id | string | `imap email id` | |
action_result.parameter.container_id | string | `phantom container id` | |
action_result.parameter.folder | string | | |
action_result.parameter.ingest_email | boolean | | |
action_result.data.\*.message | string | | |
action_result.data.\*.container_id | numeric | | |
action_result.data.\*.ARC-Authentication-Results | string | | |
action_result.data.\*.ARC-Message-Signature | string | | |
action_result.data.\*.ARC-Seal | string | | |
action_result.data.\*.Accept-Language | string | | |
action_result.data.\*.Authentication-Results | string | | |
action_result.data.\*.CC | string | | |
action_result.data.\*.Content-Language | string | | |
action_result.data.\*.Content-Transfer-Encoding | string | | |
action_result.data.\*.Content-Type | string | | |
action_result.data.\*.DKIM-Signature | string | | |
action_result.data.\*.Date | string | | |
action_result.data.\*.Delivered-To | string | | |
action_result.data.\*.FCC | string | | |
action_result.data.\*.Feedback-ID | string | | |
action_result.data.\*.From | string | | |
action_result.data.\*.In-Reply-To | string | | |
action_result.data.\*.MIME-Version | string | | |
action_result.data.\*.Message-ID | string | | |
action_result.data.\*.Received | string | | |
action_result.data.\*.Received-SPF | string | | |
action_result.data.\*.References | string | | |
action_result.data.\*.Reply-To | string | | |
action_result.data.\*.Return-Path | string | `email` | |
action_result.data.\*.Subject | string | | |
action_result.data.\*.Thread-Index | string | | |
action_result.data.\*.Thread-Topic | string | | |
action_result.data.\*.To | string | | |
action_result.data.\*.User-Agent | string | | |
action_result.data.\*.X-Account-Key | string | | |
action_result.data.\*.X-Gm-Message-State | string | | |
action_result.data.\*.X-Google-DKIM-Signature | string | | |
action_result.data.\*.X-Google-Id | string | | |
action_result.data.\*.X-Google-Smtp-Source | string | | |
action_result.data.\*.X-Identity-Key | string | | |
action_result.data.\*.X-MS-Exchange-Organization-AuthAs | string | | |
action_result.data.\*.X-MS-Exchange-Organization-AuthMechanism | string | | |
action_result.data.\*.X-MS-Exchange-Organization-AuthSource | string | | |
action_result.data.\*.X-MS-Exchange-Organization-SCL | string | | |
action_result.data.\*.X-MS-Has-Attach | string | | |
action_result.data.\*.X-MS-TNEF-Correlator | string | | |
action_result.data.\*.X-Mozilla-Draft-Info | string | | |
action_result.data.\*.X-Received | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
