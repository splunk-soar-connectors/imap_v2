**Unreleased**

* - Updated the Splunk SOAR SDK to version 3.26.0 to incorporate the latest OAuth and email handling improvements.
* - Required encrypted IMAP authentication by default and stopped continuing after a failed STARTTLS upgrade.
* - Added IMAP server certificate verification with the SOAR CA bundle and an explicit compatibility opt-out.
* - Validated email UIDs and safely quoted mailbox names to prevent authenticated IMAP command injection.
* - Marked get email as state-changing because its ingest option can write attachments to the SOAR vault.
* - Held polling checkpoints at the first failed email so transient parsing failures are retried instead of skipped.
