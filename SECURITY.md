# Security Policy

Report suspected Zeek vulnerabilities privately through the
[Zeek security reporting process](https://zeek.org/security-reporting/). If you
have evidence that hostile or restricted input may violate a property in the
[Zeek Security Model](SECURITY_MODEL.md) but are unsure how to classify it,
report it privately and allow the Zeek Team to decide.

Do not open a public issue or pull request, or publish a reproducer or proposed
fix, until the team confirms that public development is appropriate. Follow the
reporting website for current instructions. If sensitive captures or
large binary artifacts are needed, describe them in the initial report and ask
the team how to transfer them.

## What to Include

Provide enough information to reproduce and assess the behavior when
available:

- the affected Zeek version or commit, platform, build type, and configuration;
- who controls the input and what access or deployment conditions are needed;
- a minimal reproducer and exact steps, including expected and actual behavior;
- the observed impact and whether it affects live traffic, supplied captures,
  cluster or service interfaces, or local inputs; and
- any relevant release-build, sanitizer, resource, or regression-test results.

A patch, regression test, CVSS score, sanitizer result, or validation across
every supported branch can help, but none is required for an initial private
report. Clearly distinguish confirmed observations from hypotheses.

The team makes final decisions about classification, severity, disclosure,
affected versions, and release coordination. Zeek's actors, trust boundaries,
and protected security properties are described in the security model.

The
[Security Release Process](https://github.com/zeek/zeek/wiki/Security-Release-Process)
describes coordinated security releases.
