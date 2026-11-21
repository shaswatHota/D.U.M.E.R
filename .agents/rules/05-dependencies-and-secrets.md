---
trigger: always_on
description: Supply-chain and secret hygiene
---
- Do not install third-party agent skills, MCP servers, browser extensions, or scripts into this project without owner approval; review their source first.
- Pin dependencies (lockfile committed); pin model files and tools by SHA-256; fetch only from official sources over HTTPS.
- Never paste real keys, tokens, IDs, personal data, or private hostnames into code, docs, tests, or logs. Use obviously fake fixtures.
- Don't run networked, destructive, or privileged commands in the dev environment without telling the owner exactly what and why.
