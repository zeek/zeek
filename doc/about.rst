==========
About Zeek
==========

What Is Zeek?
=============

Zeek is a passive, open-source network traffic analyzer. Many operators use
Zeek as a network security monitor (NSM) to support investigations of
suspicious or malicious activity. Zeek also supports a wide range of traffic
analysis tasks beyond the security domain, including performance measurement
and troubleshooting.

The first benefit a new user derives from Zeek is the extensive set of logs
describing network activity. These logs include not only a comprehensive record
of every connection seen on the wire, but also application-layer transcripts.
These include all HTTP sessions with their requested URIs, key headers, MIME
types, and server responses; DNS requests with replies; SSL certificates; key
content of SMTP sessions; and much more. By default, Zeek writes all this
information into well-structured tab-separated or JSON log files suitable for
post-processing with external software. Users can also choose to have external
databases or SIEM products consume, store, process, and present the data for
querying.

In addition to the logs, Zeek comes with built-in functionality for a range of
analysis and detection tasks, including extracting files from HTTP sessions,
detecting malware by interfacing to external registries, reporting vulnerable
versions of software seen on the network, identifying popular web applications,
detecting SSH brute-forcing, validating SSL certificate chains, and much more.

In addition to shipping such powerful functionality “out of the box,” Zeek is a
fully customizable and extensible platform for traffic analysis. Zeek provides
users a domain-specific, Turing-complete scripting language for expressing
arbitrary analysis tasks. Think of the Zeek language as a “domain-specific
Python” (or Perl): just like Python, the system comes with a large set of
pre-built functionality (the “standard library”), yet users can also put Zeek
to use in novel ways by writing custom code. Indeed, all of Zeek’s default
analyses, including logging, are done via scripts; no specific analysis is
hard-coded into the core of the system.

Zeek runs on commodity hardware and hence provides a low-cost alternative to
expensive proprietary solutions. In many ways Zeek exceeds the capabilities of
other network monitoring tools, which typically remain limited to a small set
of hard-coded analysis tasks. Zeek is not a classic signature-based intrusion
detection system (IDS); while it supports such standard functionality as well,
Zeek’s scripting language facilitates a much broader spectrum of very different
approaches to finding malicious activity. These include semantic misuse
detection, anomaly detection, and behavioral analysis.

A large variety of sites deploy Zeek to protect their infrastructure, including
many universities, research labs, supercomputing centers, open-science
communities, major corporations, and government agencies. Zeek specifically
targets high-speed, high-volume network monitoring, and an increasing number of
sites are now using the system to monitor their 10GE networks, with some
already moving on to 100GE links.

Zeek accommodates high-performance settings by supporting scalable
load-balancing. Large sites typically run “Zeek Clusters” in which a high-speed
front end load balancer distributes the traffic across an appropriate number of
back end PCs, all running dedicated Zeek instances on their individual traffic
slices. A central manager system coordinates the process, synchronizing state
across the back ends and providing the operators with a central management
interface for configuration and access to aggregated logs. Zeek’s integrated
management framework, ZeekControl, supports such cluster setups out-of-the-box.

Zeek’s cluster features support single-system and multi-system setups. That's
part of Zeek’s scalability advantages. For example, administrators can scale
Zeek within one system for as long as possible, and then transparently add more
systems when necessary.

In brief, Zeek is optimized for interpreting network traffic and generating
logs based on that traffic. It is not optimized for byte matching, and users
seeking signature detection approaches would be better served by trying
intrusion detection systems such as Suricata. Zeek is also not a protocol
analyzer in the sense of Wireshark, seeking to depict every element of network
traffic at the frame level, or a system for storing traffic in packet capture
(PCAP) form. Rather, Zeek sits at the “happy medium” representing compact yet
high fidelity network logs, generating better understanding of network traffic
and usage.

Why Zeek?
=========

Zeek offers many advantages for security and network teams who want to better
understand how their infrastructure is being used.

Security teams generally depend upon four sorts of data sources when trying to
detect and respond to suspicious and malicious activity. These include *third
party* sources such as law enforcement, peers, and commercial or nonprofit
threat intelligence organizations; *network data*; *infrastructure and
application data*, including logs from cloud environments; and *endpoint data*.
Zeek is primarily a platform for collecting and analyzing the second form of
data -- network data. All four are important elements of any security team’s
program, however.

When looking at data derived from the network, there are four types of data
available to analysts. As defined by the `network security monitoring paradigm
<https://corelight.blog/2019/04/30/do-you-know-your-nsm-data-types/>`_, these
four data types are *full content*, *transaction data*, *extracted content*,
and *alert data*. Using these data types, one can record traffic, summarize
traffic, extract traffic (or perhaps more accurately, extract content
in the form of files), and judge traffic, respectively.

It’s critical to collect and analyze the four types of network security
monitoring data. The question becomes one of determining the best way to
accomplish this goal. Thankfully, Zeek as a NSM platform enables collection of
at least two, and in some ways three, of these data forms, namely  transaction
data, extracted content, and alert data.

Zeek is best known for its transaction data. By default, when run and told to
watch a network interface, Zeek will generate a collection of compact,
high-fidelity, richly-annotated set of transaction logs. These logs describe
the protocols and activity seen on the wire, in a judgement-free,
policy-neutral manner. This documentation will spend a considerable amount of
time describing the most common Zeek log files such that readers will become
comfortable with the format and learn to apply them to their environment.

Zeek can also easily carve files from network traffic, thanks to its file
extraction capabilities. Analysts can then send those files to execution
sandboxes or other file examination tools for additional investigation. Zeek
has some capability to perform classical byte-centric intrusion detection, but
that job is best suited for packages like the open source Snort or Suricata
engines. Zeek has other capabilities however that are capable of providing
judgements in the form of alerts, through its notice mechanism.

Zeek is not optimized for writing traffic to disk in the spirit of a full
content data collection, and that task is best handled by software written to
fulfill that requirement.

Beyond the forms of network data that Zeek can natively collect and generate,
Zeek has advantages that appeared in the `What Is Zeek?`_ section. These
include its built-in functionality for a range of analysis and detection
tasks, and its status as a fully customizable and extensible platform for
traffic analysis.  Zeek is also attractive because of its ability to run on
commodity hardware, giving users of all types the ability to at least try Zeek
in a low-cost manner.

History
=======

Zeek has a rich history stretching back to the 1990s. `Vern Paxson
<http://www.icir.org/vern/>`_ designed and implemented the initial version in
1995 as a researcher at the `Lawrence Berkeley National Laboratory (LBNL)
<http://www.lbl.gov/>`_. The original software was called “Bro,” as an
“Orwellian reminder that monitoring comes hand in hand with the potential
for privacy violations”.

LBNL first deployed Zeek in 1996, and the USENIX Security Symposium published
Vern’s original paper on Zeek in 1998, and awarded it the Best Paper Award that
year He published a refined version of the paper in 1999 as `Bro: A System for
Detecting Network Intruders in Real-Time
<http://www.icir.org/vern/papers/bro-CN99.pdf>`_.

In 2003, the `National Science Foundation (NSF) <http://www.nsf.gov/>`_ began
supporting research and advanced development on Bro at the `International
Computer Science Institute (ICSI) <http://www.icsi.berkeley.edu/>`_. (Vern
still leads the ICSI `Networking and Security group <http://www.icir.org/>`_.)

Over the years, a growing team of ICSI researchers and students kept adding
novel functions to Zeek, while LBNL continued its support with funding from the
`Department of Energy (DOE) <http://www.doe.gov/>`_. Much of Zeek’s
capabilities originate in academic research projects, with results often
published at top-tier conferences. A key to Zeek’s success was the project’s
ability to bridge the gap between academia and operations. This relationship
helped ground research on Zeek in real-world challenges.

With a growing operational user community, the research-centric development
model eventually became a bottleneck to the system’s evolution.  Research
grants did not support the more mundane parts of software development and
maintenance. However, those elements were crucial for the end-user experience.
As a result, deploying Zeek required overcoming a steep learning curve.

In 2010, NSF sought to address this challenge by awarding ICSI a grant from its
Software Development for Cyberinfrastructure fund. The `National Center for
Supercomputing Applications (NCSA) <http://www.ncsa.illinois.edu/>`_ joined the
team as a core partner, and the Zeek project began to overhaul many of the
user-visible parts of the system for the 2.0 release in 2012.

After Zeek 2.0, the project enjoyed tremendous growth in new deployments across
a diverse range of settings, and the ongoing collaboration between ICSI (co-PI
Robin Sommer) and NCSA (co-PI Adam Slagell) brought a number of important
features.  In 2012, Zeek added native IPv6 support, long before many enterprise
networking monitoring tools. In 2013, NSF renewed its support with a second
grant that established the Bro Center of Expertise at ICSI and NCSA, promoting
Zeek as a comprehensive, low-cost security capability for research and
education communities. To facilitate both debugging and education,
`try.zeek.org <https://try.zeek.org>`_ (formerly try.bro.org) was launched in
2014.  This provided an interactive way for users to test a script with their
own packet captures against a variety of Zeek versions and easily share
sample code with others.  For Zeek clusters and external communication,
the Broker communication framework was added.  Last, but not least, the
Zeek package manager was created in 2016, funded by an additional grant
from the Mozilla Foundation.

In the fall of 2018, the project leadership team decided to change the name of
the software from Bro to Zeek. The leadership team desired a name that better
reflected the values of the community while avoiding the negative connotations
of so-called “bro culture” outside the computing world. The project released
version 3.0 in the fall of 2019, the first release bearing the name Zeek. The
year 2020 saw a renewed focus on community and growing the Zeek community, with
increased interaction via social media, webinars, Slack channels, and related
outreach efforts.

For a history of the project from 1995 to 2015, see Vern Paxson’s talk from
BroCon 2015, `Reflecting on Twenty Years of Bro
<https://www.youtube.com/watch?v=pb9HlmV0s2A>`_.

For background on the decision to rename Bro to Zeek, see Vern Paxson’s talk
from BroCon 2018, `Renaming Bro
<https://www.youtube.com/watch?v=L88ZYfjPzyk>`_.

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
