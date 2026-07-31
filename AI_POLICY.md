# AI Usage Policy

Zeek accepts AI-assisted contributions only when a human contributor takes
responsibility for the complete submission. The following rules apply:

- **Disclose any AI assistance.** State the tool, the extent of assistance,
  and the model when it is readily available. For a pull request or issue, one
  disclosure in its main description is sufficient; for standalone
  communication, disclose it there. For example:
  `AI assistance: <tool> [<model, if known>] was used for <scope>. I reviewed
  and edited the complete submission.` Do not include prompts or transcripts
  unless requested and safe to share.

- **The human contributor owns the complete submission.** Before a contribution
  is made public or presented for maintainer review, review and edit the
  complete diff and communication. Understand the changed code, relevant
  interfaces, tests, and failure modes, and be able to explain the change and
  answer substantive review questions in your own words. Do not submit an
  unfinished AI-generated draft for maintainers to complete.

- **AI-assisted work has the same quality requirements as other work.**
  Verify generated code, tests, documentation, citations, and baselines against
  the repository and authoritative references. Run the relevant checks and
  accurately report their results, including any relevant checks that were not
  run. Never treat a result merely predicted by an AI tool as evidence.

- **Protect confidential material.** Never provide credentials or secrets to
  an AI service. Do not provide private traffic captures, personal data, or
  other confidential material unless you are authorized to share it and the
  data owner or their organization has approved the service for that class of
  data. Do not provide nonpublic vulnerability reports, reproducers, or fixes
  to an external AI service without approval from the Zeek Security Team
  (ZST). If AI-assisted work newly reveals a plausible vulnerability in public
  source, follow `SECURITY.md` before sharing additional private artifacts or
  continuing external submission.

- **No AI-generated media is allowed (art, images, videos, audio, etc.).**
  Text, code, and PCAPs, subject to the other rules in this policy, are the
  acceptable forms of AI-generated content.

- **AI-generated PCAP files require submission of source code.** Packet
  captures created by AI-generated scripts or code, such as Python's Scapy
  library, are acceptable when they follow the same disclosure rules. The
  generator for `<name>.pcap` must be checked in as `<name>.pcap.py`, and
  running it must reproduce the capture. Add an entry to
  `testing/btest/Traces/README` that identifies the AI generation and the
  script.

## There are Humans Here

Please remember that Zeek is maintained by humans.

Every discussion, issue, and pull request is read and reviewed by humans (and
sometimes machines, too). It is a boundary point at which people interact with
each other and the work done. It is rude and disrespectful to approach this
boundary with low-effort, unqualified work, since it puts the burden of
validation on the maintainer.

In a perfect world, AI would produce high-quality, accurate work every time.
But today, that reality depends on the driver of the AI. And today, most
drivers of AI are just not good enough. So, until either the people get better,
the AI gets better, or both, we have to have strict rules to protect
maintainers.

**Our reason for the strict AI policy is not due to an anti-AI stance**, but
instead due to inconsiderate use of AI.

This policy is based on the
[Ghostty AI Usage Policy](https://github.com/ghostty-org/ghostty/blob/main/AI_POLICY.md).
