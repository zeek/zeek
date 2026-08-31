# Zeek Security Model

## Purpose

Zeek processes network data that may be controlled by an adversary. This
document describes the actors, trust boundaries, and security properties used
when designing Zeek and assessing potential vulnerabilities.

This model guides engineering and triage. It does not replace the
[security reporting process](SECURITY.md) or the Security Release Process. The
Zeek Security Team (ZST) makes final decisions about scope, severity,
disclosure, and supported-version impact.

For deployment hardening, see the
[Security Considerations](doc/security-considerations.rst).

## System Context

Zeek analyzes live network traffic and supplied packet captures. Packet,
session, protocol, and file analyzers convert that input into events consumed
by the runtime, scripts, logging, storage, and other integrations.

Deployments may also expose cluster, messaging, WebSocket, telemetry, input,
storage, and other service interfaces. Zeek scripts, packages, and native
plugins extend the process with administrator-granted authority.

A value does not become trusted merely because it has moved from an analyzer
into an event, script value, log record, cluster message, or storage request.

## Actors and Trust Boundaries

### Untrusted Inputs

The following can be controlled by an attacker and must be treated as
untrusted at their processing boundary:

- Observed network traffic. A sender may control packet bytes without having
  direct access to the sensor.
- Supplied PCAP and PCAPNG files, including packet contents, link types,
  timestamps, lengths, and container metadata.
- Files and other content reconstructed from network sessions.
- Counts, lengths, offsets, names, events, and other runtime values derived
  from untrusted traffic or captures.

Not all untrusted inputs are the same. Any vulnerability that is only
exploitable through PCAP files, for example, would be far less severe
than one that applies to live traffic.

### Restricted or Deployment-Dependent Inputs

Some interfaces are intended to be isolated or available only to authorized
clients:

- Cluster transports and serialized cluster messages.
- Broker, ZeroMQ, WebSocket, and other management or integration interfaces.
- Input-framework records, telemetry endpoints, and storage backends.
- Replies from DNS servers, storage services, and other configured peers.

An assessment must identify who can reach or control the interface, its
default bind and authentication configuration, and the authority granted to an
authorized client.

Cluster peers can communicate as equal. This means they can trigger events, see
log streams, or even execute code, on peers. That is not a vulnerability.
Regardless, cluster peers should preserve memory safety, availability, and
process integrity. Any entity that communicates event traffic in the cluster
is considered a peer including, for example, websocket clients.

The input framework (and any frameworks which rely on it) are seen as trusted
input. However, they may cross a security boundary when a remote actor can
control these inputs.

Documented access, such as an authorized client publishing or subscribing to
events, is not itself a vulnerability. Inputs received through these
interfaces must nevertheless preserve memory safety, availability, and
process integrity.

### Trusted Administrative Inputs

The security model normally trusts:

- Loaded Zeek scripts, packages, and native plugins.
- Command-line options and administrator-provided configuration.
- The Zeek executable, installation, library and executable search paths, and
  host environment.
- Actors with authority equivalent to the Zeek process or its administrator.

A defect rooted in a third-party component can still affect Zeek when that
component is shipped or reachable through a supported Zeek deployment. Report
it privately so the team can coordinate ownership and disclosure. Zeek-owned
integration, configuration, and validation errors remain within Zeek's
boundary.

## Protected Security Properties

When handling untrusted or restricted input, Zeek should preserve:

1. **Process and host integrity.** Input must not cause memory corruption,
   arbitrary code execution, privilege escalation, or unauthorized
   modification of system assets.
2. **Availability.** Input must not cause unbounded persistent state,
   unbounded or materially amplified attacker-selected allocation,
   disproportionate computation, excessive recursion, or strongly amplified
   disk or event output. Effective protocol limits and analysis budgets may
   provide bounds. Resource use proportional to sustained traffic is normally
   an operational capacity concern unless persistence or amplification makes
   the impact materially disproportionate.
3. **Analysis integrity.** Input must not allow an attacker to silently and
   materially desynchronize parsing, detach an analyzer, suppress
   security-relevant events or logs, or misrepresent traffic accepted by a
   real supported endpoint in a way that hides activity. Visible rejection of
   malformed or unsupported input in the form of weirds, analyzer violations,
   or other logging is not, by itself, a violation.
4. **Confidentiality.** Analysis must not disclose captured or site-local
   information to unauthorized actors or through unintended outbound
   activity.
5. **Boundary enforcement.** Configured authentication, authorization, and
   transport protections must not be bypassed.
6. **Failure containment.** Malformed input should be rejected or reported
   without corrupting other flows, contaminating unrelated state, or losing
   unrelated analysis.

Breaking any of these properties is not automatically considered a vulnerability, but is
instead a candidate for assessment. How the property is broken helps to determine
classification. The default expsure of the break may change the severity.

A deviation from these properties is a candidate for assessment, not
automatically a vulnerability. Actor, reachability, materiality, and whether
the affected functionality is supported or experimental inform classification.
Configuration and default exposure inform severity.

## Assessment Principles

A security assessment should:

1. Identify the exact attacker-controlled input and trace it to the affected
   operation or state.
2. State the actor, required access, deployment assumptions, and
   configuration.
3. Confirm reachability in a supported production-style build when practical.
   AddressSanitizer can establish a reachable memory-safety defect even when a
   release build does not visibly fail; the sanitizer termination itself does
   not establish operational impact or severity. A fatal condition present in
   a production build and reached from the assessed untrusted or restricted
   input is concrete process unavailability; the actor and preconditions still
   determine classification. A debug-only assertion can be supporting evidence.
4. Establish material impact, such as corruption, process failure,
   disproportionate resource amplification, material loss of analysis,
   disclosure, or an unauthorized side effect.
5. Distinguish unbounded or amplified work from resource use proportional to
   sustained traffic volume.
6. For analysis differences, identify the event, log, state, or security
   signal that is lost or falsified.
7. Record whether the affected functionality is supported or explicitly
   experimental. Supported functionality remains in scope whether or not it is
   enabled by default; default configuration and experimental status inform
   exposure and severity.
8. Identify whether the root cause belongs to Zeek, a shipped integration, a
   generator, or a third-party component.
9. Separate confirmed observations from assumptions and provisional severity.

A visible and contained rejection of malformed input normally does not
establish a security issue. Neither does a harmless output difference without
demonstrated operational or analysis impact.

When classification is uncertain but a plausible boundary and material impact
exist, report the issue privately and allow the team to classify it.

## Classification Boundaries

The following do not establish a remote vulnerability by themselves:

- Behavior requiring control of loaded scripts, native plugins, packages, the
  installation, or an equivalent host environment.
- Capabilities intentionally granted to authorized cluster or API clients.
- A third-party defect that is not reachable through a supported Zeek
  deployment and has no Zeek-owned integration or validation error.
- Visible rejection of malformed or unsupported input without unrelated loss
  of analysis.
- Capacity exhaustion caused only by traffic volume proportional to expected
  processing cost.
- A diagnostic, warning, or sanitizer report that has not been confirmed as a
  reachable violation of a protected security property.
- Missing support for protocol features does not constitute a security issue.

## Severity and Reporting

Input origin, access requirements, default configuration, supported-version
impact, exploitability, and consequence all inform severity. Running Zeek with
elevated privileges can increase consequences, but does not change who
controls an input.

Potential vulnerabilities should be handled according to
[SECURITY.md](SECURITY.md), which owns the current reporting and disclosure
instructions.
