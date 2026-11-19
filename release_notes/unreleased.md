**Unreleased**

* Require Splunk SOAR SDK 7.2.4 to ingest email attachments while preserving threat-analysis and automation flags.
* Report rejected credentials or authorization as `reason=authentication` and mailbox selection failures as `reason=mailbox`, without exposing server responses, credentials, or mailbox names. Network failures remain generic; classic polling is unchanged.
