===============================
Zeek for SOC Analysts: Practical Detection Guide
===============================

Introduction
============

Zeek is a network security monitoring framework that provides high‑fidelity,
protocol‑level visibility into network activity. While Zeek is widely deployed
across enterprise, academic, and government environments, many SOC analysts
struggle to interpret Zeek logs, pivot between data sources, and apply Zeek
effectively during threat hunting and incident response.

This guide provides a practical, analyst‑focused introduction to Zeek. It
explains how to interpret core Zeek logs, detect common adversary behaviors,
and use Zeek data in investigations. All detection concepts in this guide are
grounded in authoritative sources, including Zeek documentation, MITRE ATT&CK,
NIST, CISA, SANS, and peer‑reviewed research.

Core Zeek Logs for SOC Analysis
===============================

Zeek generates many logs, but a small subset forms the foundation of most SOC
investigations. The following sections summarize the purpose of each log,
important fields, and suspicious indicators. Log field definitions are based on
the official Zeek Logs Reference (Zeek Documentation).

conn.log — Connection Metadata
------------------------------

The ``conn.log`` file records metadata for every observed network connection.

Key fields (Zeek Logs Reference):

* ``id.orig_h`` / ``id.resp_h`` — source and destination IPs
* ``id.orig_p`` / ``id.resp_p`` — ports
* ``proto`` — protocol (TCP/UDP/ICMP)
* ``duration`` — connection length
* ``conn_state`` — final connection state
* ``history`` — sequence of TCP flags

Suspicious indicators (MITRE ATT&CK: Discovery, Command and Control):

* High volume of short‑lived connections (scanning)
* Repeated failed connections (reconnaissance)
* Long‑duration connections with low data transfer (beaconing)
* Unusual ports or protocols

dns.log — DNS Activity
----------------------

DNS is a rich source of adversary behavior.

Key fields:

* ``query`` — domain name
* ``qtype_name`` — record type (A, AAAA, TXT, etc.)
* ``answers`` — resolved IPs
* ``rcode_name`` — response code

Suspicious indicators (CISA DNS Security Guidance, SANS DNS Tunneling):

* High‑entropy or algorithmically generated domains (DGA)
* Excessive TXT queries (tunneling)
* Long subdomain chains
* Rapid‑fire DNS lookups

http.log — Web Traffic
----------------------

HTTP logs reveal malware delivery, C2 traffic, and exfiltration.

Key fields:

* ``method`` — GET, POST, PUT
* ``uri`` — requested path
* ``user_agent`` — client identifier
* ``status_code`` — server response

Suspicious indicators (MITRE ATT&CK: Exfiltration, Initial Access):

* Rare or malformed user agents
* Large POST requests (exfiltration)
* Repeated 404 responses (probing)
* Suspicious file downloads

tls.log — Encrypted Traffic Metadata
------------------------------------

TLS logs help analysts understand encrypted sessions without decrypting traffic.

Key fields:

* ``ja3`` / ``ja3s`` — TLS client/server fingerprints (Salesforce JA3 Research)
* ``version`` — TLS version
* ``cipher`` — negotiated cipher suite
* ``server_name`` — SNI

Suspicious indicators (NIST SP 800‑52, CISA TLS Hardening):

* Deprecated TLS versions (1.0/1.1)
* Self‑signed or mismatched certificates
* JA3/JA3S fingerprints associated with malware
* TLS sessions without SNI

ssh.log — SSH Activity
----------------------

SSH is commonly used for brute force attacks and lateral movement.

Suspicious indicators (MITRE ATT&CK: Credential Access, Lateral Movement):

* Repeated failed logins
* Unusual SSH client versions
* SSH from unexpected networks

files.log — File Metadata
-------------------------

Zeek tracks files transferred over the network.

Suspicious indicators (CISA Malware Delivery Guidance):

* Executable files downloaded over HTTP
* High‑entropy files (encrypted payloads)
* Unexpected file types

Practical Detection Techniques
==============================

The following detection patterns are grounded in MITRE ATT&CK, SANS network
forensics guidance, and peer‑reviewed research.

Detecting Scanning
------------------

Indicators:

* Many short connections (``duration < 1s``)
* Repeated ``S0`` or ``REJ`` states
* Sequential port sweeps

(MITRE ATT&CK: Discovery)

Detecting Beaconing
-------------------

Indicators (SANS Beaconing Analysis):

* Regular connection intervals
* Same destination IP
* Small, consistent data sizes
* Long‑running TCP sessions

(MITRE ATT&CK: Command and Control)

Detecting DNS Tunneling
-----------------------

Indicators (SANS DNS Tunneling, CISA DNS Security):

* Long subdomains
* High entropy in ``query``
* Excessive TXT queries
* Large DNS response sizes

Detecting Suspicious TLS
------------------------

Indicators (NIST SP 800‑52, JA3 Research):

* Deprecated cipher suites
* Invalid certificates
* JA3/JA3S fingerprints linked to malware
* TLS without SNI

Detecting Long‑Duration Connections
-----------------------------------

Indicators (MITRE ATT&CK: Exfiltration, C2):

* ``duration > 1 hour``
* Low byte counts
* Unusual destination networks

Incident Response Workflow with Zeek
====================================

This workflow is aligned with NIST SP 800‑61 (Incident Response) and SANS IR
methodology.

Start with conn.log
-------------------

Identify:

* Suspicious IPs
* Unusual ports
* Long durations
* Failed connections

Pivot to dns.log
----------------

Check:

* Domains queried by the suspicious host
* DGA‑like patterns
* Newly registered domains (MITRE ATT&CK: TA0011)

Pivot to http.log
-----------------

Look for:

* Suspicious downloads
* Rare user agents
* Unexpected POST requests

Pivot to tls.log
----------------

Check:

* JA3/JA3S fingerprints
* Certificate anomalies
* Deprecated TLS versions

Pivot to files.log
------------------

Identify:

* Malware downloads
* Suspicious file types
* High‑entropy payloads

Using Zeek Logs in SIEM Platforms
=================================

These examples follow vendor documentation (Splunk, Elastic, Microsoft
Sentinel) and NIST SP 800‑92 (Log Management).

Splunk — Detect Beaconing
-------------------------

::

   index=zeek sourcetype=zeek_conn
   | stats count avg(duration) by id.resp_h
   | where count > 20 AND avg(duration) < 2

Elastic — Suspicious DNS
------------------------

::

   dns.question.type : "TXT" AND dns.question.name.keyword : "*.long-subdomain*"

Sentinel — TLS Anomalies
------------------------

::

   ZeekTLS
   | where tls_version < "TLSv1.2"

Mapping Zeek Logs to MITRE ATT&CK
=================================

+-------------+---------------------------+-------------------------------+
| Zeek Log    | ATT&CK Technique          | Example                       |
+=============+===========================+===============================+
| dns.log     | TA0011 Command & Control | DGA, tunneling                |
+-------------+---------------------------+-------------------------------+
| http.log    | TA0010 Exfiltration      | Large POST requests           |
+-------------+---------------------------+-------------------------------+
| tls.log     | TA0001 Initial Access    | Suspicious certificates       |
+-------------+---------------------------+-------------------------------+
| conn.log    | TA0007 Discovery         | Port scanning                 |
+-------------+---------------------------+-------------------------------+
| ssh.log     | TA0006 Credential Access | Brute force                   |
+-------------+---------------------------+-------------------------------+

References
==========

Primary Sources
