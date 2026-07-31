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

An input being untrusted does not determine severity by itself. For example,
exploitation through a supplied capture has different preconditions from
exploitation by traffic crossing a monitored link.

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

Cluster peers may communicate as equals, and some interfaces grant broad
publish or subscribe authority. Where an interface has no built-in
authentication, "authorized" means the deployment has restricted access
through binding, network isolation, or an external control.

Input-framework records are normally administrative inputs. They cross a
security boundary when a supported deployment allows a less-privileged or
remote actor to control them. Conversely, selecting a DNS, storage, or other
remote service does not make all data returned by that service trusted.

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

These inputs can intentionally exercise powerful behavior, including native
or external code execution. Surprising behavior in a shipped component may
still warrant an ordinary fix, but control of an unrestricted administrative
input is not treated as a remote boundary crossing.

A defect rooted in a third-party component can still affect Zeek when that
component is shipped or reachable through a supported Zeek deployment. Report
it privately so the ZST can coordinate ownership and disclosure. Zeek-owned
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
   malformed or unsupported input is not, by itself, a violation.
4. **Confidentiality.** Analysis must not disclose captured or site-local
   information to unauthorized actors or through unintended outbound
   activity.
5. **Boundary enforcement.** Configured authentication, authorization, and
   transport protections must not be bypassed.
6. **Failure containment.** Malformed input should be rejected or reported
   without corrupting other flows, contaminating unrelated state, or losing
   unrelated analysis.

A deviation from these properties is a candidate for assessment, not
automatically a vulnerability. Actor, reachability, configuration,
materiality, and the support status of the affected functionality determine
classification.

## Assessment Principles

A security assessment should:

1. Identify the exact attacker-controlled input and trace it to the affected
   operation or state.
2. State the actor, required access, deployment assumptions, and
   configuration.
3. Confirm reachability in a supported production-style build when practical.
   A sanitizer can establish a reachable memory-safety defect even when a
   release build does not visibly fail; the sanitizer termination itself does
   not establish operational impact or severity. A fatal condition present in
   a production build and reached from the assessed untrusted or restricted
   input is concrete process unavailability; the actor and preconditions still
   determine classification. A debug-only assertion is supporting evidence.
4. Establish material impact, such as corruption, process failure,
   disproportionate resource amplification, material loss of analysis,
   disclosure, or an unauthorized side effect.
5. Distinguish unbounded or amplified work from resource use proportional to
   sustained traffic volume.
6. For analysis differences, identify the event, log, state, or security
   signal that is lost or falsified.
7. Record whether affected functionality is enabled by default, supported but
   optional, or explicitly experimental. Supported optional functionality
   remains assessable. Experimental, preliminary, or work-in-progress
   functionality that is inactive by default generally has lower exposure and
   may receive Low or no-risk treatment.
8. Identify whether the root cause belongs to Zeek, a shipped integration, a
   generator, or a third-party component.
9. Separate confirmed observations from assumptions and provisional severity.

A visible and contained rejection of malformed input normally does not
establish a security issue. Neither does a harmless output difference without
demonstrated operational or analysis impact.

When classification is uncertain but a plausible boundary and material impact
exist, report the issue privately and allow the ZST to classify it.

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

These cases may still be ordinary correctness or robustness defects. Another
threat model may apply to Zeek's build system, software supply chain, or
developer-controlled compiler inputs.

## Severity and Reporting

Input origin, access requirements, default configuration, supported-version
impact, exploitability, and consequence all inform severity. Running Zeek with
elevated privileges can increase consequences, but does not change who
controls an input.

Potential vulnerabilities should be handled according to
[SECURITY.md](SECURITY.md), which owns the current reporting and disclosure
instructions.
