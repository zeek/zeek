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
