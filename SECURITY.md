# Security policy

This project is for authorized evaluation against local, deliberately vulnerable
services. Do not configure it to target a public or third-party system.

## Required boundaries

- Model credentials stay in the host environment and never enter actor tools.
- Actor requests use the allowlisted HTTP tool and a fixed local origin.
- Raw transcripts and oracle data remain under `data/raw_restricted/`.
- Defender packets contain no credentials, canaries, prompts, condition labels, or
  provider identifiers.
- Real target containers must not have public Internet egress or non-loopback host
  exposure.

Any exception must be recorded in `SAFETY_DEVIATIONS.md` before data collection.

