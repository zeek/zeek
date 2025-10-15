============================
known_*.log and software.log
============================

Zeek produces several logs that help summarize certain aspects of the network
it monitors. These logs track a few aspects of the local network, such as
SSL/TLS certificates, host IP addresses, services, and applications.

The sections which follow will present examples of entries in
:file:`known_certs.log`, :file:`known_hosts.log`, :file:`known_services.log`,
and :file:`software.log` files collected on live networks.

For full details on each field of those log files, see
:zeek:see:`Known::CertsInfo`, :zeek:see:`Known::HostsInfo`,
:zeek:see:`Known::ServicesInfo`, and :zeek:see:`Software::Info`.

:file:`known_certs.log`
=======================

The :file:`known_certs.log` captures information about SSL/TLS certificates
seen on the local network. Here is one example::

  {
    "ts": "2020-12-31T15:15:53.690221Z",
    "host": "192.168.4.1",
    "port_num": 443,
    "subject": "L=San Jose,ST=CA,O=Ubiquiti Networks,CN=UBNT Router UI,C=US",
    "issuer_subject": "L=San Jose,ST=CA,O=Ubiquiti Networks,CN=UBNT Router UI,C=US",
    "serial": "98D0AD47D748CDD6"
  }

This example shows a device offering a TLS server on port 443 TCP, with a
certificate associated with Ubiquiti Networks.

:file:`known_hosts.log`
=======================

The :file:`known_hosts.log` simply records a timestamp and an IP address when
Zeek observes a new system on the local network.

::

  {"ts":"2021-01-03T01:19:26.260073Z","host":"192.168.4.25"}
  {"ts":"2021-01-03T01:19:27.353353Z","host":"192.168.4.29"}
  {"ts":"2021-01-03T01:19:32.488179Z","host":"192.168.4.43"}
  {"ts":"2021-01-03T01:19:58.792683Z","host":"192.168.4.142"}
  ...edited...
  {"ts":"2021-01-03T12:17:22.496004Z","host":"192.168.4.115"}

This edited example shows how this log could be part of an IP address inventory
program.

:file:`known_services.log`
==========================

The :file:`known_services.log` records a timestamp, IP, port number, protocol,
and service (if available) when Zeek observes a system offering a new service
on the local network. Here is what a single entry looks like::

  {
    "ts": "2021-01-03T01:19:36.242774Z",
    "host": "192.168.4.1",
    "port_num": 53,
    "port_proto": "udp",
    "service": [
      "DNS"
    ]
  }

For the following list, I used the :program:`jq` utility to remove the
timestamp but show the other log values.

::

  ["192.168.4.43",51472,"tcp",[]]
  ["192.168.4.1",443,"tcp",["SSL"]]
  ["192.168.4.1",80,"tcp",["HTTP"]]
  ["192.168.4.1",22,"tcp",["SSH"]]
  ["192.168.4.1",53,"tcp",["DNS"]]
  ["192.168.4.1",123,"udp",["NTP"]]
  ["192.168.4.50",49745,"tcp",[]]
  ["192.168.4.158",4500,"udp",[]]
  ["192.168.4.159",53032,"tcp",[]]
  ["192.168.4.142",36807,"udp",[]]
  ["192.168.4.1",53,"udp",["DNS"]]
  ["192.168.4.149",8080,"tcp",["HTTP"]]
  ["192.168.4.1",67,"udp",["DHCP"]]
  ["192.168.4.43",64744,"tcp",[]]
  ["192.168.4.43",52793,"tcp",[]]
  ["192.168.4.29",52827,"tcp",[]]
  ["192.168.4.43",64807,"tcp",[]]
  ["192.168.4.43",64752,"tcp",[]]
  ["192.168.4.149",3478,"udp",[]]

Note how many of the services do not have names associated with them.

:file:`software.log`
====================

Zeek’s :file:`software.log` collects details on applications operated by the
hosts it sees on the local network. The log captures information like the
following::

  {
    "ts": "2021-01-03T00:16:22.694616Z",
    "host": "192.168.4.25",
    "software_type": "HTTP::BROWSER",
    "name": "Windows-Update-Agent",
    "version.major": 10,
    "version.minor": 0,
    "version.minor2": 10011,
    "version.minor3": 16384,
    "version.addl": "Client",
    "unparsed_version": "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.0"
  }

It is amazing in 2021 that so many modern applications still use clear text
protocols subject to collection and analysis by software like Zeek.

Services beyond HTTP may also reveal interesting details. Consider these three
entries::

  ["192.168.4.1","SSH::SERVER","OpenSSH",6,6,1,null,"p1","OpenSSH_6.6.1p1 Debian-4~bpo70+1"]
  ["192.168.4.37","SSH::CLIENT","OpenSSH",6,6,1,null,"p1","OpenSSH_6.6.1p1 Debian-4~bpo70+1"]
  ["192.168.4.37","SSH::CLIENT","OpenSSH",7,6,null,null,"p1","OpenSSH_7.6p1"]

These examples show an SSH server and two different SSH clients.

Conclusion
==========

Details recorded in :file:`known_certs.log`, :file:`known_hosts,log`,
:file:`known_services.log`, and :file:`software.log` files can help network and
security analysts better understand the nature of the activity in their
environment. Some of this information relies on capturing clear text, while
other aspects are based solely on the presence of the services and hosts on the
network.
