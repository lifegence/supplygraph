# Security Policy

SupplyGraph helps teams respond to vulnerabilities, so we take vulnerabilities in SupplyGraph itself seriously.

## Supported versions

SupplyGraph is pre-1.0. Security fixes go to the `main` branch only. It supports Frappe v16.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**

Report it privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability** ([private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).

Please include:

- the affected version or commit,
- the steps to reproduce, or a proof of concept,
- the impact you expect (for example, who can do what they should not be able to),
- whether the issue is already public.

Use only your own test site and synthetic data. Do not send us real SBOMs or other data from your company or your customers.

## What to expect

- We acknowledge the report within 5 business days (JST).
- We confirm the issue, agree on a fix and a disclosure date with you, and publish a GitHub Security Advisory with the fix. We request a CVE when it applies.
- We credit you in the advisory unless you ask us not to.

## Scope

In scope: the code in this repository (the `supplygraph` Frappe app).

Out of scope:

- vulnerabilities in Frappe Framework or other dependencies — report them to their maintainers (for Frappe: <https://github.com/frappe/frappe/security>);
- findings that need administrator access, or that only affect a site in developer mode;
- vulnerability data that SupplyGraph imports from OSV; report wrong advisories to their source.
