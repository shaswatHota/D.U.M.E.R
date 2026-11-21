---
name: dumer-research-gateway
description: Build the isolated web research gateway, outbound query firewall, SSRF/DNS-rebinding protections, and freshness-class TTL knowledge cache. Use for any internet access or web-derived knowledge.
---
# Research gateway
- Separate OS account/AppContainer, clean profile (no cookies/passwords/extensions/sign-ins), no access to home, clipboard, SSH keys, app DBs; downloads to quarantine; read-only first (no forms/purchases/messages/uploads).
- Egress only via allowlisting proxy: block RFC1918, loopback, link-local, CGNAT, cloud-metadata IPs, IPv6 equivalents; resolve DNS at connect time and pin the IP; cap redirects, size, content types, time.
- Query firewall (deterministic): length → identifier denylist (hashes/Bloom of owner's names, handles, emails, phone, IDs) → PII regexes → canary check → entropy/key detector → hash-only log. Hit ⇒ block and tell the user.
- Prefer self-hosted metasearch + page extraction. Third-party chat-AI browsing: optional plugin, off by default, anonymous session, sanitized generic questions only; may violate site terms.
- Output is text + provenance, labelled `Web`-tainted. Never instructions.
- Cache: classes static/slow/fast/volatile with TTL caps; deterministic classifier (keywords, Cache-Control/Last-Modified, user pin); stale-while-revalidate for slow; volatile never persisted; the LLM cannot extend TTL.
- Tests: SSRF/rebinding/redirect abuse, hostile pages, oversize, identifier-in-query blocked, canary exfil, cache TTL/class behaviour.
