Architecture
============

.. image:: /images/architecture.png
   :align: center
   :scale: 75%

At a very high level, Zeek is architecturally layered into two major
components. Its *event engine* (or *core*) reduces the incoming packet stream
into a series of higher-level *events*. These events reflect network activity
in policy-neutral terms, i.e., they describe *what* has been seen, but not
*why*, or whether it is significant.

For example, every HTTP request on the wire turns into a corresponding
:zeek:see:`http_request` event that carries with it the involved IP addresses
and ports, the URI being requested, and the HTTP version in use. The event
however does not convey any further *interpretation*, such as whether that URI
corresponds to a known malware site.

The event engine component comprises a number of subcomponents, including in
particular the packet processing pipeline consisting of: input sources,
packet analysis, session analysis, and file analysis. Input sources ingest
incoming network traffic from network interfaces. Packet analysis processes
lower-level protocols, starting all the way down at the link layer. Session
analysis handles application-layer protocols, such as HTTP, FTP, etc. File
analysis dissects the content of files transferred over sessions. The event
engine provides a plugin architecture for adding any of these from outside
of the core Zeek code base, allowing to expand Zeek’s capabilities as
needed.

Semantics related to the events are derived by Zeek’s second main component,
the *script interpreter*, which executes a set of *event handlers* written in
Zeek’s custom scripting language. These scripts can express a site’s
security policy, such as what actions to take when the monitor detects
different types of activity.

More generally scripts can derive any desired properties and statistics from
the input traffic. In fact, all of Zeek’s default output comes from scripts
included in the distribution. Zeek’s language comes with extensive
domain-specific types and support functionality. Crucially, Zeek’s language
allows scripts to maintain state over time, enabling them to track and
correlate the evolution of what they observe across connection and host
boundaries. Zeek scripts can generate real-time alerts and also execute
arbitrary external programs on demand. One might use this functionality to
trigger an active response to an attack.
