# Account Compromise — Synthetic Demo

Subject: alex.morgan@example.test
Host: WIN-ACCT-014
Suspicious source: 203.0.113.77
Suspicious session: SESS-1002

## Investigation hypothesis
An unfamiliar successful login is followed by an MFA change,
password reset, mailbox-rule creation, contact export, OAuth
consent, and an external email.

## Correlation tasks
- Build a chronological timeline across all three evidence files.
- Correlate events using the account, source IP, and session ID.
- Identify the first suspicious event.
- Link every finding to its source evidence.
- Flag conclusions as hypotheses until validated.

All data is fictional. Documentation-only IP addresses are used.
This dataset does not establish that a real account was compromised.
