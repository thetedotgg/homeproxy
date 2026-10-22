# Security policy

HomeProxy handles household traffic, proxy passwords and, when you enable it, a local certificate authority. Please report vulnerabilities privately so they can be fixed before details are public.

## Reporting

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on <https://github.com/thetedotgg/homeproxy>. Do not open a public issue for a vulnerability.

Include the HomeProxy version, platform (Windows or Ubuntu), the affected component and steps to reproduce. Do not include real proxy passwords, certificate private keys, browsing history or diagnostic exports from other people's networks.

I aim to acknowledge reports within 7 days. Fixes are released as a new version on the [releases page](https://github.com/thetedotgg/homeproxy/releases); the report is credited unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: proxy authentication and device blocking, the local control socket and its permissions, certificate authority storage and HTTPS inspection, cache privacy rules (cookies, authorization, `private`, `no-store`), installer and package scripts.

Out of scope: attacks that require an already compromised administrator account on the computer running HomeProxy, and denial of service from devices you have allowed on your own network.
