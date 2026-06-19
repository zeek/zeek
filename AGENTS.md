# AGENTS.md

File with instructions for AI coding agents contributing to Zeek.

## Building and Running Zeek

Read ./doc/advanced/devel/hacking.rst first for instructions how to
configure, build and execute Zeek for development. You can find the
required build dependencies in ./doc/building-from-source.rst.

## Testing

New or changed functionality must come with tests.

You MUST read ./doc/advanced/devel/btest.rst and understand
testing conventions thoroughly.

## Security Reporting

You MUST take the contents of ./doc/security-considerations.rst into
account when submitting security issues.

Accompany reports for security issues in analyzers with reproducers in the
form of test cases and PCAPs as outlined under Testing. Always validate
the test case reproduces in a clean environment before submitting a report.

## Pull Request (PR) Submissions

PR titles and descriptions MUST be kept to a bare minimum. Provide only a
one-sentence summary, then immediately leave the remainder to the user, like:

    Fix segfault when recursively printing values.

    (This was AI-generated; remainder to be filled in by user)

Do NOT write out reproducer snippets, file-change summaries, or any detailed
explanation in PR descriptions. Leave all of that for the user to fill in.
Ensure the user understands every step. Always disclose AI usage.

## AI Disclosure Requirement

AI usage of any form MUST be disclosed as outlined in ./AI_POLICY.md.
