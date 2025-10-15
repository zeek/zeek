
.. _zkg package manager: https://docs.zeek.org/projects/package-manager/en/stable/

=======================================
SMB Logs (plus DCE-RPC, Kerberos, NTLM)
=======================================

Server Message Block (SMB) is a protocol most commonly associated with
Microsoft Windows enterprise administration. While there are implementations
for other operating systems, such as Linux, Mac OS, FreeBSD, and the like, many
security and network analysts seek information on SMB due to its use in Windows
environments.

Introduction
============

For the most part, the log analysis sections of this document address a single
Zeek log, such as :file:`conn.log` or :file:`dns.log`. When Zeek encounters SMB
protocol usage, it usually creates multiple logs of varying types. In addition
to the ubiquitous :file:`conn.log`, Zeek may generate :file:`dce_rpc.log`,
:file:`kerberos.log`, :file:`ntlm.log`, :file:`smb_cmd.log`,
:file:`smb_files.log`, :file:`smb_mapping.log`, :file:`pe.log`, and even
:file:`notice.log` entries.

This section will build upon a paper by Nate Marx published December 20, 2017
titled “An Introduction to SMB for Network Security Analysts.” The paper
analyzes a set of packet captures that contain activity in a simulated
compromised Windows environment.

The paper is available here:

https://401trg.github.io/pages/an-introduction-to-smb-for-network-security-analysts.html

The packet captures are available here:

https://github.com/401trg/detections/tree/master/pcaps

Thorough documentation of several versions of SMB are available online thanks
to Microsoft.

SMB version 1 is posted here:

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/f210069c-7086-4dc2-885e-861d837df688

SMB versions 2 and 3 are posted here:

https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962

For information on the individual field values in these SMB-affiliated logs,
please refer to :zeek:see:`DCE_RPC::Info`, :zeek:see:`KRB::Info`,
:zeek:see:`NTLM::Info`, :zeek:see:`SMB::CmdInfo`, :zeek:see:`SMB::FileInfo`,
and :zeek:see:`SMB::TreeInfo`.

When presenting information in this section, my general convention is to bold
commands and items of interest in the resulting output.

Leveraging BZAR
===============

Before looking at individual logs associated with SMB, it’s helpful to first
consider adding the BZAR package to your repertoire.

BZAR stands for Bro/Zeek ATT&CK-based Analytics and Reporting. Mark Fernandez
and others from MITRE and the Zeek community wrote BZAR to generate
:file:`notice.log` entries when certain patterns of activity appear in some SMB
logs.

You can learn more about BZAR at https://github.com/mitre-attack/bzar and install
it via the `zkg package manager`_ by saying

.. literal-emph::

   zkg install bzar

I suggest using BZAR when one first begins looking at SMB logs. Without BZAR,
it could be difficult to know what might be worth investigating and what might
be normal. However, even with BZAR, it is no easy feat to differentiate among
normal, suspicious, and malicious SMB activity. Still, leveraging the BZAR
policy script for Zeek will give analysts a place to begin their
investigations.

Running the ``net user`` Command
================================

Let’s start our investigation of SMB logs with the case labelled “RPC” in Nate
Marx’s paper. The relevant packet capture file is titled
:file:`20171220_smb_net_user.pcap`.

If we process the packet capture with Zeek and BZAR, the following files appear:

* :file:`conn.log`
* :file:`dce_rpc.log`
* :file:`kerberos.log`
* :file:`notice.log`
* :file:`packet_filter.log`
* :file:`smb_mapping.log`

Let’s look at the :file:`conn.log` first to get a general overview of the
traffic.

.. literal-emph::

  {
    "ts": 1507562478.10937,
    "uid": "CzgIrZ31Lh5vCHioWi",
    **"id.orig_h": "192.168.10.31",**
    "id.orig_p": 49282,
    **"id.resp_h": "192.168.10.10",**
    **"id.resp_p": 445,**
    "proto": "tcp",
    "service": "gssapi,smb,dce_rpc,krb",
    "duration": 0.22932004928588867,
    "orig_bytes": 16271,
    "resp_bytes": 13720,
    "conn_state": "S1",
    "missed_bytes": 0,
    "history": "ShADda",
    "orig_pkts": 78,
    "orig_ip_bytes": 19403,
    "resp_pkts": 77,
    "resp_ip_bytes": 16812
  }

We see that ``192.168.10.31`` initiated a connection to ``192.168.10.10``. The
destination port is 445 TCP, which is associated with SMB activity. Note that
Zeek observed the services on this connection as ``gssapi,smb,dce_rpc,krb``,
which represents Generic Security Service Application Programming Interface,
Server Message Block, Distributed Computing Environment Remote Procedure Call,
and Kerberos.

The GSS-API reference likely relates to authentication, as noted in the Windows
protocol guide for SMB versions 2 and 3. It does not produce any logs named
``gssapi``. SMB is expected as we are looking for it in this case, and will
create smb-named logs. DCE-RPC is a protocol associated with Windows networking
and command execution between machines, and will likely create a
:file:`dce_rpc.log` entry. Kerberos is an authentication protocol that will
likely create a :file:`kerberos.log` entry.

:file:`notice.log`
------------------

Let’s see what the :file:`notice.log` has to say about this activity.

.. literal-emph::

  {
    "ts": 1507562478.117387,
    **"note": "ATTACK::Discovery",**
    **"msg": "Detected activity from host 192.168.10.31, total attempts 5 within timeframe 5.0 mins",**
    "actions": [
      "Notice::ACTION_LOG"
    ],
    "suppress_for": 3600
  }
  {
    "ts": 1507562478.124176,
    **"note": "ATTACK::Discovery",**
    **"msg": "Detected activity from host 192.168.10.31, total attempts 10 within timeframe 5.0 mins",**
    "actions": [
      "Notice::ACTION_LOG"
    ],
    "suppress_for": 3600
  }
  {
    "ts": 1507562478.138992,
    **"note": "ATTACK::Discovery",**
    **"msg": "Detected activity from host 192.168.10.31, total attempts 15 within timeframe 5.0 mins",**
    "actions": [
      "Notice::ACTION_LOG"
    ],
    "suppress_for": 3600
  }

These three entries all indicate the same sort of activity: ``192.168.10.31``
is doing some sort of “discovery” action. We do not know the nature of the
reconnaissance nor do we know the target. However, when combined with the
:file:`conn.log` we saw previously, we can assume that ``192.168.10.10`` is the
target.

:file:`dce_rpc.log`
-------------------

The :file:`notice.log` alerted us to suspicious or malicious activity from
``192.168.10.31``. Perhaps the :file:`dce_rpc.log` can help us understand what
is happening?

Let’s look at the first entry in :file:`dce_rpc.log`.

.. literal-emph::

  {
    "ts": 1507562478.112879,
    "uid": "CzgIrZ31Lh5vCHioWi",
    **"id.orig_h": "192.168.10.31",**
    "id.orig_p": 49282,
    **"id.resp_h": "192.168.10.10",**
    **"id.resp_p": 445,**
    "rtt": 0.0003020763397216797,
    **"named_pipe": "\\pipe\\lsass",**
    **"endpoint": "samr",**
    **"operation": "SamrConnect5"**
  }

This entry shows that ``192.168.10.31`` connected to ``192.168.10.10`` via a
named pipe titled ``lsass``. Microsoft’s documentation says “a pipe is a
section of shared memory that processes use for communication. The process that
creates a pipe is the pipe server. A process that connects to a pipe is a pipe
client… Named pipes can be used to provide communication between processes on
the same computer or between processes on different computers across a
network.”

Ref: https://docs.microsoft.com/en-us/windows/win32/ipc/pipes

The lsass named pipe refers to the Local Security Authority Subsystem Service
(LSASS). The endpoint, ``samr``, refers to the Security Accounts Manager.
Microsoft’s documentation says “the SamrConnect5 method obtains a handle to a
server object.”

Ref: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/c842a897-0a42-4ca5-a607-2afd05271dae

Even if you do not fully understand all of these details (and who does!), it
appears that ``192.168.10.31`` is trying to remotely access ``192.168.10.10``
in a way that requires security authentication on the client, via DCE-RPC over
SMB.

All of the entries in the :file:`dce_rpc.log` have the same source and
destination addresses and ports. We can summarize them by extracting only the
relevant fields using :program:`jq`:

If we look at every one of the 46 entries in the :file:`dce_rpc.log`, we will
see repeats of some commands. These do not add to our general understanding of
what is happening. To show a reduced set of commands, I invoke :program:`jq`
and pipe the output through uniq to only show unique outputs:

.. code-block:: console

  $ jq -c '[."named_pipe", ."endpoint", ."operation"]' dce_rpc.log | uniq

.. literal-emph::

  ["\\pipe\\lsass","samr","SamrConnect5"]
  ["\\pipe\\lsass","samr","**SamrEnumerateDomainsInSamServer**"]
  ["\\pipe\\lsass","samr","SamrLookupDomainInSamServer"]
  ["\\pipe\\lsass","samr","SamrOpenDomain"]
  ["\\pipe\\lsass","samr","**SamrLookupNamesInDomain**"]
  ["\\pipe\\lsass","samr","SamrOpenUser"]
  ["\\pipe\\lsass","samr","**SamrQueryInformationUser**"]
  ["\\pipe\\lsass","samr","SamrQuerySecurityObject"]
  ["\\pipe\\lsass","samr","**SamrGetGroupsForUser**"]
  ["\\pipe\\lsass","samr","SamrGetAliasMembership"]
  ["\\pipe\\lsass","samr","SamrCloseHandle"]
  ["\\pipe\\lsass","samr","SamrConnect5"]
  ["\\pipe\\lsass","samr","SamrEnumerateDomainsInSamServer"]
  ["\\pipe\\lsass","samr","SamrLookupDomainInSamServer"]
  ["\\pipe\\lsass","samr","SamrOpenDomain"]
  ["\\pipe\\lsass","samr","SamrQueryInformationDomain"]
  ["\\pipe\\lsass","samr","SamrCloseHandle"]
  ["\\pipe\\lsass","lsarpc","LsarOpenPolicy2"]
  ["\\pipe\\lsass","lsarpc","LsarQueryInformationPolicy"]
  ["\\pipe\\lsass","samr","SamrConnect5"]
  ["\\pipe\\lsass","samr","SamrOpenDomain"]
  ["\\pipe\\lsass","samr","SamrCloseHandle"]
  ["\\pipe\\lsass","lsarpc","LsarLookupNames3"]
  ["\\pipe\\lsass","samr","SamrGetAliasMembership"]
  ["\\pipe\\lsass","samr","SamrCloseHandle"]
  ["\\pipe\\lsass","lsarpc","LsarClose"]
  ["\\pipe\\lsass","samr","SamrConnect5"]
  ["\\pipe\\lsass","samr","SamrEnumerateDomainsInSamServer"]
  ["\\pipe\\lsass","samr","SamrLookupDomainInSamServer"]
  ["\\pipe\\lsass","samr","SamrOpenDomain"]
  ["\\pipe\\lsass","samr","SamrLookupNamesInDomain"]
  ["\\pipe\\lsass","samr","SamrOpenUser"]
  ["\\pipe\\lsass","samr","SamrGetGroupsForUser"]
  ["\\pipe\\lsass","samr","SamrLookupIdsInDomain"]
  ["\\pipe\\lsass","samr","SamrCloseHandle"]

The bolded entries indicate that ``192.168.10.31`` is performing some sort of
user enumeration against ``192.168.10.10``. Again, we don’t necessarily know
exactly what all of this means, but if there is no reason from
``192.168.10.31`` to be performing this action, then it’s worth investigating!

:file:`kerberos.log` and :file:`smb_mapping.log`
------------------------------------------------

Let’s see if the :file:`kerberos.log` has anything new to add to our
investigation.

.. literal-emph::

  {
    "ts": 1507562478.110863,
    "uid": "CzgIrZ31Lh5vCHioWi",
    **"id.orig_h": "192.168.10.31",**
    "id.orig_p": 49282,
    **"id.resp_h": "192.168.10.10",**
    **"id.resp_p": 445**
  }

These are the same details we found through the :file:`conn.log`, but it
confirms that Zeek identified Kerberos authentication in use.

The :file:`smb_mapping.log` offers one entry as well:

.. literal-emph::

  {
    "ts": 1507562478.111677,
    "uid": "CzgIrZ31Lh5vCHioWi",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49282,
    "id.resp_h": "192.168.10.10",
    "id.resp_p": 445,
    **"path": "\\\\DC1.contoso.local\\IPC$",**
    "share_type": "PIPE"
  }

Here we see the first mention of the ``IPC$`` share. As noted in Mr. Marx’s
paper, Windows uses the ``IPC$`` share as a means to enable remote procedure
calls. We knew this was the case when we reviewed the :file:`dce_rpc.log`. It’s
possible that the ``DC1`` in the path value for this log means that
``192.168.10.10`` is a domain controller. It’s likely that there is user
reconnaissance occurring.

If we look at the explanation for this activity noted in Mr. Marx’s paper, he
says that a simulated intruder on ``192.168.10.31`` executed the ``net user``
command against ``192.168.10.10``. The intruder took this action to enumerate
the user list on the target.

In the next two cases we will see what it looks like when simulated intruders move files from one system to another.

Connecting to a SMB Share and Uploading a File
==============================================

We continue our exploration of SMB logs by reviewing the first case discussed
in Mr. Marx’s paper. The relevant packet capture file is titled
:file:`20171220_smb_mimikatz_copy.pcap`. Mr. Marx’s discussion appears in the
section “The Basics” in his paper.

If we process the packet capture with Zeek and BZAR, the following files appear:

* :file:`conn.log`
* :file:`extract_files/`
* :file:`files.log`
* :file:`kerberos.log`
* :file:`notice.log`
* :file:`packet_filter.log`
* :file:`pe.log`
* :file:`smb_files.log`
* :file:`smb_mapping.log`

Let’s look at the :file:`conn.log` first to get a general overview of the
traffic.

:file:`conn.log`
----------------

The :file:`conn.log` has two entries:

.. literal-emph::

  {
    "ts": 1507565438.203425,
    "uid": "CR7Vww4LuLkMzi4jMd",
    **"id.orig_h": "192.168.10.31",**
    "id.orig_p": 49238,
    **"id.resp_h": "192.168.10.30",**
    **"id.resp_p": 445,**
    "proto": "tcp",
    **"service": "krb,smb,gssapi",**
    "duration": 1.1398930549621582,
    "orig_bytes": 814051,
    "resp_bytes": 11657,
    "conn_state": "S1",
    "missed_bytes": 0,
    "history": "ShADda",
    "orig_pkts": 66,
    "orig_ip_bytes": 816703,
    "resp_pkts": 91,
    "resp_ip_bytes": 15309
  }
  {
    "ts": 1507565425.183882,
    "uid": "CyeWAg1QrRKQL0HHMi",
    "id.orig_h": "192.168.10.30",
    "id.orig_p": 138,
    **"id.resp_h": "192.168.10.255",**
    **"id.resp_p": 138,**
    "proto": "udp",
    "conn_state": "S0",
    "missed_bytes": 0,
    "history": "D",
    "orig_pkts": 1,
    "orig_ip_bytes": 207,
    "resp_pkts": 0,
    "resp_ip_bytes": 0
  }

The first entry shows a connection initiated by ``192.168.10.31`` to
``192.168.10.30``.

The second entry is likely a SMB-related Windows broadcast, as seen by the
destination IP address of ``192.168.10.255``. According to a Wireshark decode
of that datagram, it’s a Windows Browser Protocol message, namely a "Become
backup browser" command with the "browser to promote" being "VICTIM-PC".
“Browser” in this case does not refer to a Web browser; it’s about accessing
resources on the local network.

Let’s next turn to the :file:`notice.log`.

:file:`notice.log`
------------------

I have selected examples of the two unique log types appearing in
:file:`notice.log`.

.. literal-emph::

  {
    "ts": 1507565439.130425,
    **"uid": "CR7Vww4LuLkMzi4jMd",**
    **"id.orig_h": "192.168.10.31",**
    "id.orig_p": 49238,
    **"id.resp_h": "192.168.10.30",**
    "id.resp_p": 445,
    "proto": "tcp",
    **"note": "ATTACK::Lateral_Movement",**
    **"msg": "Detected SMB::FILE_WRITE to admin file share '\\\\admin-pc\\c$temp\\mimikatz.exe'",**
    **"sub": "T1021.002 Remote Services: SMB/Windows Admin Shares + T1570 Lateral Tool Transfer",**
    **"src": "192.168.10.31",**
    **"dst": "192.168.10.30",**
    "p": 445,
    "actions": [
      "Notice::ACTION_LOG"
    ],
    "suppress_for": 3600
  }

  {
    "ts": 1507565439.343318,
    "uid": "CR7Vww4LuLkMzi4jMd",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49238,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    "fuid": "FwVZpk12AKBjE11UNg",
    "file_mime_type": "application/x-dosexec",
    "file_desc": "temp",
    "proto": "tcp",
    **"note": "ATTACK::Lateral_Movement_Extracted_File",**
    **"msg": "Saved a copy of the file written to SMB admin file share",**
    **"sub": "CR7Vww4LuLkMzi4jMd_FwVZpk12AKBjE11UNg__admin-pc_c$temp_mimikatz.exe",**
    **"src": "192.168.10.31",**
    **"dst": "192.168.10.30",**
    "p": 445,
    "actions": [
      "Notice::ACTION_LOG"
    ],
    "suppress_for": 3600
  }

My processing of the packet capture produced 13 of the first entry and 1 of the
second entry.

These two entries in the :file:`notice.log` tell us a lot, but also provide
material for additional investigation.

First, the note, msg, and sub entries of each log provide useful information.

Both notes relate to “lateral movement.” If a new analyst is not familiar with
that term, the sub field in the first log entry provides a reference to “T1570
Lateral Tool Transfer.” T1570 refers to the MITRE ATT&CK technique number 1570,
which is described here:

https://attack.mitre.org/techniques/T1570/

The ATT&CK Web site explains Lateral Tool Transfer thus:

  “**Adversaries may transfer tools or other files between systems in a
  compromised environment**. Files may be copied from one system to another to
  stage adversary tools or other files over the course of an operation.
  Adversaries may copy files laterally between internal victim systems to
  support lateral movement using inherent file sharing protocols such as file
  sharing over **SMB** to connected network shares or with authenticated
  connections with **SMB/Windows Admin Shares** or Remote Desktop Protocol. Files
  can also be copied over on Mac and Linux with native tools like scp, rsync,
  and sftp.” (emphasis added)

With this understanding, the msg from the first log makes more sense::

  Detected SMB::FILE_WRITE to admin file share '\\\\admin-pc\\c$temp\\mimikatz.exe'

Zeek is trying to tell us that the BZAR script detected a transfer of a file
called ``mikikatz.exe``.

The details from the second log tell us what actions Zeek took when it noticed
this activity::

  "msg": "Saved a copy of the file written to SMB admin file share",
  "sub": "CR7Vww4LuLkMzi4jMd_FwVZpk12AKBjE11UNg__admin-pc_c$temp_mimikatz.exe",

This means we should be able to look in a directory associated with our run of
Zeek to find an extracted copy of this file.

Finally, as with many Zeek logs, we have an id (in this case,
``CR7Vww4LuLkMzi4jMd``), and IP addresses which we can use to pivot through other
Zeek data. Note the src and dst entries in both logs indicate that
``192.168.10.31`` copied a file to ``192.168.10.30``.

:file:`extract_files/`, :file:`files.log`, and :file:`pe.log`, and VirusTotal
-----------------------------------------------------------------------------

Next, let’s look for the extracted file. We can use the Linux :program:`file`
command to get some details:

.. code-block:: console

  $ file extract_files/CR7Vww4LuLkMzi4jMd_FwVZpk12AKBjE11UNg__admin-pc_c\$temp_mimikatz.exe

::

  extract_files/CR7Vww4LuLkMzi4jMd_FwVZpk12AKBjE11UNg__admin-pc_c$temp_mimikatz.exe: PE32+ executable (console) x86-64, for MS Windows

As we learned in the :file:`files.log` documentation, we can look in that data
for similar information on extracted files:

.. literal-emph::

  {
    "ts": 1507565439.130425,
    "fuid": "FwVZpk12AKBjE11UNg",
    "uid": "CR7Vww4LuLkMzi4jMd",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49238,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445
    "source": "SMB",
    "depth": 0,
    "analyzers": [
      "SHA1",
      "SHA256",
      "PE",
      "MD5",
      "EXTRACT"
    ],
    **"mime_type": "application/x-dosexec",**
    **"filename": "temp\\mimikatz.exe",**
    "duration": 0.0034439563751220703,
    "is_orig": true,
    "seen_bytes": 804352,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": true,
    **"md5": "2c527d980eb30daa789492283f9bf69e",**
    "sha1": "d007f64dae6bc5fdfe4ff30fe7be9b7d62238012",
    "sha256": "fb55414848281f804858ce188c3dc659d129e283bd62d58d34f6e6f568feab37",
    "extracted": "CR7Vww4LuLkMzi4jMd_FwVZpk12AKBjE11UNg__admin-pc_c$temp_mimikatz.exe",
    "extracted_cutoff": false
  }

Here I highlighted the MIME type, showing a Windows executable, as well as the
filename, which includes a directory.

Let’s take a quick look at the :file:`pe.log` entry:

.. literal-emph::

  {
    "ts": 1507565439.130425,
    "id": "FwVZpk12AKBjE11UNg",
    "machine": "AMD64",
    **"compile_ts": 1502638084,**
    "os": "Windows XP x64 or Server 2003",
    "subsystem": "WINDOWS_CUI",
    "is_exe": true,
    "is_64bit": true,
    "uses_aslr": true,
    "uses_dep": true,
    "uses_code_integrity": false,
    "uses_seh": true,
    "has_import_table": true,
    "has_export_table": false,
    "has_cert_table": false,
    "has_debug_data": false,
    "section_names": [
      ".text",
      ".rdata",
      ".data",
      ".pdata",
      ".rsrc",
      ".reloc"
    ]
  }

There’s some interesting information in this log, like the compile time. We can
convert it to a human readable form using the Linux :program:`date` command.


.. code-block:: console

  $ date -d @1502638084

::

  Sun Aug 13 15:28:04 UTC 2017

Finally, we can use the md5 from the :file:`file.log` entry to query
VirusTotal, as we also did previously:

.. code-block:: console

  $ vt file "2c527d980eb30daa789492283f9bf69e"

::

  - _id: "fb55414848281f804858ce188c3dc659d129e283bd62d58d34f6e6f568feab37"
    _type: "file"
    authentihash: "02c86c9977c85a08f18ac1dae02f1cdda569eaba51ec6d17aed6f4ebc2adaf21"
    creation_date: 1502638084  # 2017-08-13 15:28:04 +0000 UTC
    crowdsourced_yara_results:
    - description: "mimikatz"
      rule_name: "mimikatz"
      ruleset_id: "00043243d1"
      ruleset_name: "gen_mimikatz"
      source: "https://github.com/Neo23x0/signature-base"
    - description: "Detects Mimikatz strings"
      rule_name: "Mimikatz_Strings"
      ruleset_id: "00043243d1"
      ruleset_name: "gen_mimikatz"
      source: "https://github.com/Neo23x0/signature-base"
    - description: "Detects Mimikatz SkeletonKey in Memory"
      rule_name: "HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1"
      ruleset_id: "00043243d1"
      ruleset_name: "gen_mimikatz"
      source: "https://github.com/Neo23x0/signature-base"
    - description: "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"
      rule_name: "Powerkatz_DLL_Generic"
      ruleset_id: "000d2a7a67"
      ruleset_name: "gen_powerkatz"
      source: "https://github.com/Neo23x0/signature-base"
    - description: "Detects Mimikatz by using some special strings"
      rule_name: "Mimikatz_Gen_Strings"
      ruleset_id: "000be577b3"
      ruleset_name: "thor-hacktools"
      source: "https://github.com/Neo23x0/signature-base"
    first_submission_date: 1502652611  # 2017-08-13 19:30:11 +0000 UTC
    last_analysis_date: 1602435563  # 2020-10-11 16:59:23 +0000 UTC

I reproduced the first set of results generated by VirusTotal’s
crowdsourced_yara_results to show that this is indeed a copy of Mimikatz, the
ubiquitous credential-dumping tool used for lateral movement in Windows
environments.

:file:`kerberos.log`, :file:`smb_mapping.log`, and :file:`smb_files.log`
------------------------------------------------------------------------

We have learned that ``192.168.10.31`` copied :file:`mimikatz.exe` to
``192.168.10.30``. This is probably the most important aspect of the activity,
and it is based on BZAR’s interpretation of the SMB logs. Let’s take a quick
look at those logs to see if we can glean anything more from them.

The :file:`kerberos.log` has a single short entry:

::

  {
    "ts": 1507565438.204785,
    "uid": "CR7Vww4LuLkMzi4jMd",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49238,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445
  }

This indicates that Kerberos, an authentication measure used by Windows, had a
role in this connection.

The :file:`smb_mapping.log` also has a single short entry:

.. literal-emph::

  {
    "ts": 1507565438.205583,
    "uid": "CR7Vww4LuLkMzi4jMd",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49238,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    **"path": "\\\\admin-pc\\c$",**
    "share_type": "DISK"
  }

We see evidence of connecting to the administrative file share on
``192.168.10.30``.

The :file:`smb_files.log` has many entries. The first looks like this:

.. literal-emph::

  {
    "ts": 1507565438.205868,
    "uid": "CR7Vww4LuLkMzi4jMd",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49238,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    **"action": "SMB::FILE_OPEN",**
    **"path": "\\\\admin-pc\\c$",**
    **"name": "<share_root>",**
    "size": 4096,
    "times.modified": 1507316839.5820882,
    "times.accessed": 1507316839.5820882,
    "times.created": 1247539136.5268176,
    "times.changed": 1507316839.5820882
  }

All of the entries have the same ``uid``, ``id.orig_h``, ``id.orig_p``,
``id.resp_h``, and ``id.resp_p``. The ``size`` and ``times`` entries aren’t
especially interesting here.

I include the specific :program:`jq` syntax in case you’ve forgotten how to
tell :program:`jq` what fields you want to see:

.. code-block:: console

  $ jq -c '[."action", ."path", ."name"]' smb_files.log

::

  ["SMB::FILE_OPEN","\\\\admin-pc\\c$","<share_root>"]
  ["SMB::FILE_OPEN","\\\\admin-pc\\c$","temp"]
  ["SMB::FILE_OPEN","\\\\admin-pc\\c$","temp"]
  ["SMB::FILE_OPEN","\\\\admin-pc\\c$","temp\\mimikatz.exe"]
  ["SMB::FILE_WRITE","\\\\admin-pc\\c$","temp\\mimikatz.exe"]
  ["SMB::FILE_WRITE","\\\\admin-pc\\c$","temp\\mimikatz.exe"]
  ["SMB::FILE_OPEN","\\\\admin-pc\\c$","temp\\mimikatz.exe"]
  ["SMB::FILE_OPEN","\\\\admin-pc\\c$","temp"]
  ["SMB::FILE_OPEN","\\\\admin-pc\\c$","temp\\mimikatz.exe"]

These results do not tell us anything we did not know from the entries the BZAR
script made in the :file:`notice.log`. However, I include them here to help
show how BZAR decided to write in the :file:`notice.log` that it detected
lateral movement via the copy of the file :file:`mimikatz.exe` from
``192.168.10.31`` to ``192.168.10.30``.

Connecting to a SMB Share and Downloading a File
================================================

We continue our exploration of SMB logs by reviewing the second case discussed
in Nate Marx’s paper. The relevant packet capture file is titled
:file:`20171220_smb_mimikatz_copy_to_host.pcap`. Mr. Marx’s discussion appears
at the end of the section titled “The Basics” in his paper.

If we process the packet capture with Zeek and BZAR, the following files appear:

* :file:`conn.log`
* :file:`files.log`
* :file:`kerberos.log`
* :file:`packet_filter.log`
* :file:`pe.log`
* :file:`smb_files.log`
* :file:`smb_mapping.log`

Note that this time we do not have an :file:`extract_files/` directory nor a
:file:`notice.log`!

We’ll start with the :file:`conn.log` as we did with the previous case.

:file:`conn.log`
----------------

The :file:`conn.log` for this case has only one entry:

.. literal-emph::

  {
    "ts": 1512585460.295445,
    "uid": "C4j5Ds3VyExc2ZAOh9",
    **"id.orig_h": "192.168.10.31",**
    "id.orig_p": 1112,
    **"id.resp_h": "192.168.10.30",**
    **"id.resp_p": 445,**
    "proto": "tcp",
    "service": "krb,gssapi,smb",
    "duration": 13.435487985610962,
    "orig_bytes": 5762,
    "resp_bytes": 812728,
    "conn_state": "S1",
    "missed_bytes": 0,
    "history": "ShADda",
    "orig_pkts": 74,
    "orig_ip_bytes": 8734,
    "resp_pkts": 575,
    "resp_ip_bytes": 835740
  }

We see the same pattern: ``192.168.10.31`` initiated a connection to
``192.168.10.30``, to port 445 TCP. In the previous case and the current case,
``192.168.10.31`` connected to a Windows share on ``192.168.10.30``. What
happened next was different.

In the first case, ``192.168.10.31`` uploaded a file to ``192.168.10.30``.

In the second case, ``192.168.10.31`` downloaded a file from ``192.168.10.30``.

Now let’s look at the :file:`files.log` and :file:`pe.log`, as we do not have a
:file:`notice.log` to check.

:file:`files.log` and :file:`pe.log`
------------------------------------

We see one entry in :file:`files.log`:

.. literal-emph::

  {
    "ts": 1512585460.300969,
    "fuid": "FNMweB3f2OvTZ4UZLe",
    "uid": "CR7Vww4LuLkMzi4jMd",
    **"id.orig_h": "192.168.10.31",**
    "id.orig_p": 49238,
    **"id.resp_h": "192.168.10.30",**
    "id.resp_p": 445
    "source": "SMB",
    "source": "SMB",
    "depth": 0,
    "analyzers": [
      "PE"
    ],
    "mime_type": "application/x-dosexec",
    **"filename": "temp\\mimikatz.exe",**
    "duration": 0.010069131851196289,
    **"is_orig": false**,
    "seen_bytes": 804352,
    "total_bytes": 804352,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false
  }

This :file:`files.log` entry is similar to that seen in the previous case,
except the ``is_orig`` value is ``false``. This
indicates that ``192.168.10.30`` sent a file titled :file:`mimikatz.exe` to
``192.168.10.31``, or, said differently, ``192.168.10.31`` downloaded a file
from ``192.168.10.30``.

With either language, the file started at ``192.168.10.30`` (the responder)
and ended up on ``192.168.10.31`` (the originator).

This is the reverse of the previous case.

Here is the :file:`pe.log`:

.. literal-emph::

  {
    "ts": 1512585460.300969,
    "id": "FNMweB3f2OvTZ4UZLe",
    "machine": "AMD64",
    **"compile_ts": 1502638084,**
    "os": "Windows XP x64 or Server 2003",
    "subsystem": "WINDOWS_CUI",
    "is_exe": true,
    "is_64bit": true,
    "uses_aslr": true,
    "uses_dep": true,
    "uses_code_integrity": false,
    "uses_seh": true,
    "has_import_table": true,
    "has_export_table": false,
    "has_cert_table": false,
    "has_debug_data": false,
    "section_names": [
      ".text",
      ".rdata",
      ".data",
      ".pdata",
      ".rsrc",
      ".reloc"
    ]
  }

This output is the same as the previous case, to include the compile time.
There is a different id field because this file was transferred in a different
connection.

:file:`kerberos.log`, :file:`smb_mapping`.log, and :file:`smb_files.log`
------------------------------------------------------------------------

Let’s see what the other relevant files say.

The :file:`kerberos.log` has one entry:

::

  {
    "ts": 1512585460.296744,
    "uid": "C4j5Ds3VyExc2ZAOh9",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 1112,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445
  }

This is very similar to the previous :file:`kerberos.log` entry, because the
direction of the connection and the authentication is the same.

The :file:`smb_mapping.log` has one entry:

::

  {
    "ts": 1512585460.297722,
    "uid": "C4j5Ds3VyExc2ZAOh9",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 1112,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    "path": "\\\\admin-pc\\c$",
    "share_type": "DISK"
  }

This is also very similar to the previous :file:`smb_mapping.log` entry,
because the direction of the connection and the share access is the same.

The :file:`smb_files.log` only has two entries:

::

  {
    "ts": 1512585460.298136,
    "uid": "C4j5Ds3VyExc2ZAOh9",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 1112,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    "action": "SMB::FILE_OPEN",
    "path": "\\\\admin-pc\\c$",
    "name": "temp\\mimikatz.exe",
    "size": 804352,
    "times.modified": 1512171135.77705,
    "times.accessed": 1512585399.9219997,
    "times.created": 1512585399.9219997,
    "times.changed": 1512585399.9376247
  }
  {
    "ts": 1512585460.299373,
    "uid": "C4j5Ds3VyExc2ZAOh9",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 1112,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    "action": "SMB::FILE_OPEN",
    "path": "\\\\admin-pc\\c$",
    "name": "temp",
    "size": 0,
    "times.modified": 1512585399.9219997,
    "times.accessed": 1512585399.9219997,
    "times.created": 1512585360.2032497,
    "times.changed": 1512585399.9219997
  }

These entries are similar to those from the previous case, at least as far as
the ``id.orig_h`` and ``id.resp_h`` IP addresses and the ``id.resp_p`` port
values.

Summarizing these two logs, as we did for the previous case, yields these
values:

.. code-block:: console

  $ jq -c '[."action", ."path", ."name"]' smb_files.log

::

  ["SMB::FILE_OPEN","\\\\admin-pc\\c$","temp\\mimikatz.exe"]
  ["SMB::FILE_OPEN","\\\\admin-pc\\c$","temp"]

Looking at these logs, I would not as an analyst be able to tell exactly what
is happening here, other than to say it looks like :file:`mimikatz.exe` is
being transferred. Only the :file:`files.log` entry makes it possible to see
the direction of the transfer:

The file started at ``192.168.10.30`` and ended up on ``192.168.10.31``. This
conclusion is drawn from the originator and responder information and the
``is_orig`` value for the given entry being ``false``.

In the next section we will look at how someone might execute a file once it is
present on a target.

Scheduling Mimikatz via the At Service
======================================

The following analysis is based on the :file:`20171220_smb_at_schedule.pcap`
and appears near the end of the RPC section of Mr. Marx’s paper.

After processing the packet capture with Zeek and BZAR, we have the following
logs:

* :file:`conn.log`
* :file:`files.log`
* :file:`packet_filter.log`
* :file:`smb_files.log`

This is a short set of logs to analyze. We will start with the :file:`conn.log`.

:file:`conn.log`
----------------

Looking at the :file:`conn.log`, we see one entry:

.. literal-emph::

  {
    "ts": 1508525002.992213,
    "uid": "Cirxt14nybZjVhpOAk",
    **"id.orig_h": "192.168.10.31",**
    "id.orig_p": 49266,
    **"id.resp_h": "192.168.10.30",**
    **"id.resp_p": 445,**
    "proto": "tcp",
    **"service": "dce_rpc,smb",**
    "duration": 12.397327899932861,
    "orig_bytes": 1155,
    "resp_bytes": 1037,
    "conn_state": "OTH",
    "missed_bytes": 0,
    "history": "DdAR",
    "orig_pkts": 11,
    "orig_ip_bytes": 1595,
    "resp_pkts": 9,
    "resp_ip_bytes": 1397
  }

We see ``192.168.10.31`` initiated a connection to ``192.168.10.30``, port 445
TCP.  Zeek recognized this as DCE RPC and SMB traffic. Note that for some
reason Zeek did not create a :file:`dce_rpc.log` for this activity.

:file:`smb_files.log`
---------------------

The :file:`smb_files.log` holds the next clue to this activity. It contains
three entries:

.. literal-emph::

  {
    "ts": 1508525002.992213,
    "uid": "Cirxt14nybZjVhpOAk",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49266,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    **"action": "SMB::FILE_OPEN",**
    **"name": "atsvc",**
    "size": 0
  }
  {
    "ts": 1508525002.992213,
    "uid": "Cirxt14nybZjVhpOAk",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49266,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    **"action": "SMB::FILE_WRITE",**
    **"name": "atsvc",**
    "size": 0,
    "data_offset_req": 0,
    "data_len_req": 160
  }
  {
    "ts": 1508525002.992213,
    "uid": "Cirxt14nybZjVhpOAk",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49266,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    **"fuid": "Fw42Pp34N0CC79C5Ua",**
    **"action": "SMB::FILE_WRITE",**
    **"name": "atsvc",**
    "size": 0,
    "data_offset_req": 0,
    "data_len_req": 160
  }

We see SMB ``FILE_OPEN`` and ``FILE_WRITE`` messages to the ``atsvc``. This
indicates that ``192.168.10.31`` is accessing the Windows At service, used for
scheduling processes on Windows. Note that Windows and hence Zeek treats the At
service as a “file,” even though it is a service offered by Windows.

:file:`files.log`
-----------------

An odd result of Windows providing the At service as a “file” is that Zeek
creates a :file:`files.log` entry for it. Here is that entry:

.. literal-emph::

  {
    "ts": 1508525002.992817,
    "fuid": "Fw42Pp34N0CC79C5Ua",
    "uid": "Cirxt14nybZjVhpOAk",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49266,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    **"source": "SMB",**
    "depth": 0,
    "analyzers": [],
    **"filename": "atsvc",**
    "duration": 0.00038909912109375,
    "is_orig": true,
    "seen_bytes": 160,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false
  }

This file does not tell us anything we did not already know. Zeek did not
extract a file either, because the “file” in this instance is an abstraction
used to represent the At service on the Windows target.

Reviewing the Packet Capture with :program:`tshark`
===================================================

If administrators are authorized to use the At service to schedule jobs, from
the indicated source to the indicated destination, then it may not be possible
for a security analyst to identify this as malicious activity. We might be able
to learn a bit more about the activity by looking at the packet capture
directly.

To create the following output, I told :program:`tshark` to only display the
source IP address, the protocol, and the information field for each frame. I
also specified that it look at SMB version 2 traffic.

.. code-block:: console

  $ tshark -r 20171220_smb_at_schedule.pcap -T fields -e _ws.col.No. -e _ws.col.Source -e _ws.col.Protocol -e _ws.col.Info -Y smb2

.. literal-emph::

  **1       192.168.10.31   SMB2    Create Request File: atsvc**
  2       192.168.10.30   SMB2    Create Response File: atsvc
  3       192.168.10.31   SMB2    GetInfo Request FILE_INFO/SMB2_FILE_STANDARD_INFO File: atsvc
  4       192.168.10.30   SMB2    GetInfo Response
  5       192.168.10.31   DCERPC  Bind: call_id: 2, Fragment: Single, 3 context items: ATSVC V1.0 (32bit NDR), ATSVC V1.0 (64bit NDR), ATSVC V1.0 (6cb71c2c-9812-4540-0300-000000000000)
  6       192.168.10.30   SMB2    Write Response
  7       192.168.10.31   SMB2    Read Request Len:1024 Off:0 File: atsvc
  8       192.168.10.30   DCERPC  Bind_ack: call_id: 2, Fragment: Single, max_xmit: 4280 max_recv: 4280, 3 results: Provider rejection, Acceptance, Negotiate ACK
  **9       192.168.10.31   ATSVC   JobAdd request**
  10      192.168.10.30   SMB2    Ioctl Response, Error: STATUS_PENDING
  11      192.168.10.30   ATSVC   JobAdd response
  13      192.168.10.31   SMB2    Close Request File: atsvc
  14      192.168.10.30   SMB2    Close Response
  16      192.168.10.31   SMB2    Tree Disconnect Request
  17      192.168.10.30   SMB2    Tree Disconnect Response
  18      192.168.10.31   SMB2    Session Logoff Request
  19      192.168.10.30   SMB2    Session Logoff Response

Right away in frame 1 we see the request to create a “file” for the ``atsvc``.

Frame 9 might have the details of the Atsvc request. We can look at the details
using :program:`tshark`. The -O (capital letter O) command specifies which
layer of the decode we want to see.

.. code-block:: console

  $ tshark -r 20171220_smb_at_schedule.pcap -V -Y frame.number==9 -O atsvc

.. literal-emph::

  Frame 9: 338 bytes on wire (2704 bits), 338 bytes captured (2704 bits)
  Ethernet II, Src: 08:00:27:7f:b5:8b, Dst: 08:00:27:a1:27:e8
  Internet Protocol Version 4, Src: 192.168.10.31, Dst: 192.168.10.30
  Transmission Control Protocol, Src Port: 49266, Dst Port: 445, Seq: 636, Ack: 541, Len: 284
  NetBIOS Session Service
  SMB2 (Server Message Block Protocol version 2)
  Distributed Computing Environment / Remote Procedure Call (DCE/RPC) Request, Fragment: Single, FragLen: 160, Call: 2, Ctx: 1
  Microsoft AT-Scheduler Service, JobAdd
      Operation: JobAdd (0)
      Pointer to Servername (uint16): \\admin-pc
          Referent ID: 0x0000000000020000
          Max Count: 11
          Offset: 0
          Actual Count: 11
          Server: \\admin-pc
      Pointer to Job Info (atsvc_JobInfo)
          JobInfo
              Job Time: 47100000
              Days Of Month: 0x00000000: (No values set)
                  .... .... .... .... .... .... .... ...0 = First: First is NOT SET
                  .... .... .... .... .... .... .... ..0. = Second: Second is NOT SET
                  .... .... .... .... .... .... .... .0.. = Third: Third is NOT SET
                  .... .... .... .... .... .... .... 0... = Fourth: Fourth is NOT SET
                  .... .... .... .... .... .... ...0 .... = Fifth: Fifth is NOT SET
                  .... .... .... .... .... .... ..0. .... = Sixth: Sixth is NOT SET
                  .... .... .... .... .... .... .0.. .... = Seventh: Seventh is NOT SET
                  .... .... .... .... .... .... 0... .... = Eight: Eight is NOT SET
                  .... .... .... .... .... ...0 .... .... = Ninth: Ninth is NOT SET
                  .... .... .... .... .... ..0. .... .... = Tenth: Tenth is NOT SET
                  .... .... .... .... .... .0.. .... .... = Eleventh: Eleventh is NOT SET
                  .... .... .... .... .... 0... .... .... = Twelfth: Twelfth is NOT SET
                  .... .... .... .... ...0 .... .... .... = Thitteenth: Thitteenth is NOT SET
                  .... .... .... .... ..0. .... .... .... = Fourteenth: Fourteenth is NOT SET
                  .... .... .... .... .0.. .... .... .... = Fifteenth: Fifteenth is NOT SET
                  .... .... .... .... 0... .... .... .... = Sixteenth: Sixteenth is NOT SET
                  .... .... .... ...0 .... .... .... .... = Seventeenth: Seventeenth is NOT SET
                  .... .... .... ..0. .... .... .... .... = Eighteenth: Eighteenth is NOT SET
                  .... .... .... .0.. .... .... .... .... = Ninteenth: Ninteenth is NOT SET
                  .... .... .... 0... .... .... .... .... = Twentyth: Twentyth is NOT SET
                  .... .... ...0 .... .... .... .... .... = Twentyfirst: Twentyfirst is NOT SET
                  .... .... ..0. .... .... .... .... .... = Twentysecond: Twentysecond is NOT SET
                  .... .... .0.. .... .... .... .... .... = Twentythird: Twentythird is NOT SET
                  .... .... 0... .... .... .... .... .... = Twentyfourth: Twentyfourth is NOT SET
                  .... ...0 .... .... .... .... .... .... = Twentyfifth: Twentyfifth is NOT SET
                  .... ..0. .... .... .... .... .... .... = Twentysixth: Twentysixth is NOT SET
                  .... .0.. .... .... .... .... .... .... = Twentyseventh: Twentyseventh is NOT SET
                  .... 0... .... .... .... .... .... .... = Twentyeighth: Twentyeighth is NOT SET
                  ...0 .... .... .... .... .... .... .... = Twentyninth: Twentyninth is NOT SET
                  ..0. .... .... .... .... .... .... .... = Thirtieth: Thirtieth is NOT SET
                  .0.. .... .... .... .... .... .... .... = Thirtyfirst: Thirtyfirst is NOT SET
              Days Of Week: 0x00: (No values set)
                  .... ...0 = DAYSOFWEEK MONDAY: DAYSOFWEEK_MONDAY is NOT SET
                  .... ..0. = DAYSOFWEEK TUESDAY: DAYSOFWEEK_TUESDAY is NOT SET
                  .... .0.. = DAYSOFWEEK WEDNESDAY: DAYSOFWEEK_WEDNESDAY is NOT SET
                  .... 0... = DAYSOFWEEK THURSDAY: DAYSOFWEEK_THURSDAY is NOT SET
                  ...0 .... = DAYSOFWEEK FRIDAY: DAYSOFWEEK_FRIDAY is NOT SET
                  ..0. .... = DAYSOFWEEK SATURDAY: DAYSOFWEEK_SATURDAY is NOT SET
                  .0.. .... = DAYSOFWEEK SUNDAY: DAYSOFWEEK_SUNDAY is NOT SET
              Flags: 0x00: (No values set)
                  .... ...0 = JOB RUN PERIODICALLY: JOB_RUN_PERIODICALLY is NOT SET
                  .... ..0. = JOB EXEC ERROR: JOB_EXEC_ERROR is NOT SET
                  .... .0.. = JOB RUNS TODAY: JOB_RUNS_TODAY is NOT SET
                  .... 0... = JOB ADD CURRENT DATE: JOB_ADD_CURRENT_DATE is NOT SET
                  ...0 .... = JOB NONINTERACTIVE: JOB_NONINTERACTIVE is NOT SET
              **Pointer to Command (uint16): c:\mimikatz.exe**
                  **Referent ID: 0x0000000000020000**
                  **Max Count: 16**
                  **Offset: 0**
                  **Actual Count: 16**
                  **Command: c:\mimikatz.exe**

Once you get past the spelling errors in the “Days of Month” section, we see in
the “Pointer to Command” section a reference to :file:`c:\mimikatz.exe`. This
detail was not available in the Zeek logs, but this additional information
helps us recognize this activity as being likely malicious.

We can look to see if the command succeeded by reviewing the details of frame
11.

.. code-block:: console

  $ tshark -r 20171220_smb_at_schedule.pcap -V -Y frame.number==11 -O atsvc

.. literal-emph::

  Frame 11: 202 bytes on wire (1616 bits), 202 bytes captured (1616 bits)
  Ethernet II, Src: 08:00:27:a1:27:e8, Dst: 08:00:27:7f:b5:8b
  Internet Protocol Version 4, Src: 192.168.10.30, Dst: 192.168.10.31
  Transmission Control Protocol, Src Port: 445, Dst Port: 49266, Seq: 618, Ack: 920, Len: 148
  NetBIOS Session Service
  SMB2 (Server Message Block Protocol version 2)
  Distributed Computing Environment / Remote Procedure Call (DCE/RPC) Response, Fragment: Single, FragLen: 32, Call: 2, Ctx: 1, [Req: #9]
  Microsoft AT-Scheduler Service, JobAdd
      Operation: JobAdd (0)
      [Request in frame: 9]
      Pointer to Job Id (uint32)
          Job Id: 2
      **NT Error: STATUS_SUCCESS (0x00000000)**

The ``NT Error`` message shows ``STATUS_SUCCESS``, which indicates that the job
was scheduled via the At service.

In the next section we will introduce another capability associated with
Windows lateral movement.

Using PsExec to Retrieve a File from a Target
=============================================

Microsoft describes PsExec in the following terms:

  “PsExec is a light-weight telnet-replacement that lets you execute processes
  on other systems, complete with full interactivity for console applications,
  without having to manually install client software. PsExec's most powerful
  uses include launching interactive command-prompts on remote systems and
  remote-enabling tools like IpConfig that otherwise do not have the ability to
  show information about remote systems.”

Ref: https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

Intruders are fond of PsExec for the very capabilities that Microsoft
describes.

The following analysis is based on the
:file:`20171220_smb_psexec_mimikatz_ticket_dump.pcap` file described in the
PsExec section of Nate Marx’s paper.

Zeek creates the following output for this packet capture, along with an
:file:`extract_files/` directory. I use the :program:`wc` command to show how
many lines appear in each file.

.. code-block:: console

  $ wc -l *.log

::

    9 conn.log
   20 dce_rpc.log
    9 dns.log
    1 files.log
    2 kerberos.log
    8 notice.log
    1 packet_filter.log
    1 pe.log
    5 smb_files.log
    2 smb_mapping.log

We’ll start with the :file:`conn.log` but move to the :file:`notice.log`
quickly thereafter.

:file:`conn.log`
----------------

Because we saw that there were 9 entries in the :file:`conn.log`, I’m going to
summarize them using the following command:

.. code-block:: console

  $ jq -c '[."uid", ."id.orig_h", ."id.resp_h", ."id.resp_p", ."proto", ."service"]' conn.log

::

  ["CT7qITytKtae83Tyi","192.168.10.31","192.168.10.10",88,"tcp","krb_tcp"]
  ["CBFaLB1HJivXnb9Jw2","192.168.10.31","192.168.10.30",135,"tcp","dce_rpc"]
  ["CqgZIa4KYnX4cNHJo8","192.168.10.31","192.168.10.30",49155,"tcp","dce_rpc"]
  ["C95D4lsjb4GjGbBq2","192.168.10.31","192.168.10.255",137,"udp","dns"]
  ["CEcy2LEJUZQrLwO4b","192.168.10.31","192.168.10.10",53,"udp","dns"]
  ["CPlgJVWL9yrKdUsX8","192.168.10.31","192.168.10.10",53,"udp","dns"]
  ["C6zoLD2QgM71nvWdX5","192.168.10.30","192.168.10.255",137,"udp","dns"]
  ["C6HQVsDf8VCu0XTJe","192.168.10.31","192.168.10.30",445,"tcp","smb,krb,gssapi"]
  ["Cishox1cH3JLghxiV8","192.168.10.31","192.168.10.10",3,"icmp",null]

The 4 TCP connections likely are the sessions we want to investigate in this
case. However, because we have a :file:`notice.log` for this activity, it’s
smartest to look at those entries next.

:file:`notice.log`
------------------

The :file:`notice.log` for this activity has 8 entries. I tried to distill them
to the bare minimum required to convey what is happening, according to Zeek and
BZAR.

.. code-block:: console

  $ jq -c '[."uid", ."note", ."msg", ."sub", ."src", ."dst"]' notice.log | uniq

.. literal-emph::

  ["C6HQVsDf8VCu0XTJe","ATTACK::Lateral_Movement","Detected SMB::FILE_WRITE to admin file share '\\\\admin-pc\\ADMIN$PSEXESVC.exe'","T1021.002 Remote Services: SMB/Windows Admin Shares + **T1570 Lateral Tool Transfer**","192.168.10.31","192.168.10.30"]

  ["C6HQVsDf8VCu0XTJe","ATTACK::Lateral_Movement_Extracted_File","**Saved a copy of the file written to SMB admin file share**","C6HQVsDf8VCu0XTJe_FtIFnm3ZqI1s96P74l__admin-pc_ADMIN$**PSEXESVC.exe**","192.168.10.31","192.168.10.30"]

  ["CqgZIa4KYnX4cNHJo8","ATTACK::Execution","svcctl::CreateServiceWOW64W","T1569.002 **System Services: Service Execution**","192.168.10.31","192.168.10.30"]

  [null,"ATTACK::Lateral_Movement_and_Execution","**Detected activity against host 192.168.10.30**, total score 1004 within timeframe 10.0 mins",null,null,null]

  ["CqgZIa4KYnX4cNHJo8","ATTACK::Execution","svcctl::StartServiceW","T1569.002 System Services: **Service Execution**","192.168.10.31","192.168.10.30"]

The highlighted fields indicate suspicious or malicious activity. We see
evidence of lateral tool transfer to ``192.168.10.30`` via SMB of a file named
:file:`psexecsvc.exe`, then service execution.

:file:`dce_rpc.log`
-------------------

Let’s see if the :file:`dce_rpc.log` adds any useful details. We saw earlier
that this log has 20 entries. The first two shows us the pattern that occupies
all 20 entries.

.. literal-emph::

  {
    "ts": 1507565599.588936,
    "uid": "CBFaLB1HJivXnb9Jw2",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49240,
    **"id.resp_h": "192.168.10.30",**
    **"id.resp_p": 135,**
    "rtt": 0.0002448558807373047,
    "named_pipe": "135",
    **"endpoint": "epmapper",**
    "operation": "ept_map"
  }

  {
    "ts": 1507565599.601632,
    "uid": "CqgZIa4KYnX4cNHJo8",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49241,
    **"id.resp_h": "192.168.10.30",**
    **"id.resp_p": 49155,**
    "rtt": 0.0003237724304199219,
    "named_pipe": "49155",
    "endpoint": "svcctl",
    "operation": "OpenSCManagerW"
  }

The first entry shows a call to the Windows endpoint mapper, ``epmapper``, on
port 135 TCP on ``192.168.10.30``. The response from this service directs the
client ``192.168.10.31`` to port 49155 TCP on ``192.168.10.30``. The second and
subsequent dce_rpc.log entries involve port 49155 TCP on the target, which is
offering ``svcctrl``.

We see the target IP address is ``192.168.10.30``, confirming the activity in
the :file:`notice.log`. As we did with a previous :file:`dce_rpc.log`, we can
simplify this one into the following entries:

.. code-block:: console

  $ jq -c '[."named_pipe", ."endpoint", ."operation"]' dce_rpc.log | uniq

::

  ["135","epmapper","ept_map"]
  ["49155","svcctl","OpenSCManagerW"]
  ["49155","svcctl","CreateServiceWOW64W"]
  ["49155","svcctl","CloseServiceHandle"]
  ["49155","svcctl","OpenServiceW"]
  ["49155","svcctl","StartServiceW"]
  ["49155","svcctl","QueryServiceStatus"]
  ["49155","svcctl","CloseServiceHandle"]
  ["49155","svcctl","OpenSCManagerW"]
  ["49155","svcctl","OpenServiceW"]
  ["49155","svcctl","ControlService"]
  ["49155","svcctl","QueryServiceStatus"]
  ["49155","svcctl","CloseServiceHandle"]
  ["49155","svcctl","OpenServiceW"]
  ["49155","svcctl","DeleteService"]
  ["49155","svcctl","CloseServiceHandle"]

We see some sort of successful interaction with the ``svcctrl`` service on the target.

Incidentally, we can’t see much more using a protocol analyzer like
:program:`tshark`, either:

.. code-block:: console

  $ tshark -r 20171220_smb_psexec_mimikatz_ticket_dump.pcap -V -Y frame.number==76 -O svcctl

.. literal-emph::

  Frame 76: 258 bytes on wire (2064 bits), 258 bytes captured (2064 bits)
  Ethernet II, Src: 08:00:27:7f:b5:8b, Dst: 08:00:27:a1:27:e8
  Internet Protocol Version 4, Src: 192.168.10.31, Dst: 192.168.10.30
  Transmission Control Protocol, Src Port: 49241, Dst Port: 49155, Seq: 1945, Ack: 366, Len: 204
  Distributed Computing Environment / Remote Procedure Call (DCE/RPC) Request, Fragment: Single, FragLen: 204, Call: 2, Ctx: 0
  Microsoft Service Control, OpenSCManagerW
      Operation: OpenSCManagerW (15)
      **Encrypted stub data: 02353eb074e7e350b9632e05b550f725c99d41d419165110...**

As Mr. Marx notes in his paper, the content of these exchanges are encrypted
within the Microsoft Service Control layer.

:file:`kerberos.log`
--------------------

The :file:`kerberos.log` contains two entries:

.. literal-emph::

  {
    "ts": 1507565599.590346,
    "uid": "CT7qITytKtae83Tyi",
    **"id.orig_h": "192.168.10.31",**
    "id.orig_p": 49242,
    **"id.resp_h": "192.168.10.10",**
    **"id.resp_p": 88,**
    "request_type": "TGS",
    **"client": "RonHD/CONTOSO.LOCAL",**
    **"service": "HOST/admin-pc",**
    "success": true,
    "till": 2136422885,
    "cipher": "aes256-cts-hmac-sha1-96",
    "forwardable": true,
    "renewable": true
  }
  {
    "ts": 1507565599.575721,
    "uid": "C6HQVsDf8VCu0XTJe",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49239,
    **"id.resp_h": "192.168.10.30",**
    "id.resp_p": 445
  }

The first entry includes the acronym TGS, which means Ticket Granting service.
The system ``192.168.10.10`` appears to be a domain controller, as we saw in an
earlier case. We gather some information on the intruder’s system, namely that
it is ``RonHD`` in the ``CONTOSO.LOCAL`` domain.

The second entry shows that the aggressor ``192.168.10.31`` used Kerberos to
authenticate to the target ``192.168.10.30``.

:file:`smb_mapping.log`
-----------------------

The :file:`smb_mapping.log` contains two entries:

.. literal-emph::

  {
    "ts": 1507565599.576613,
    "uid": "C6HQVsDf8VCu0XTJe",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49239,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    **"path": "\\\\admin-pc\\ADMIN$",**
    "share_type": "DISK"
  }
  {
    "ts": 1507565599.729707,
    "uid": "C6HQVsDf8VCu0XTJe",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49239,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    **"path": "\\\\admin-pc\\IPC$",**
    "share_type": "PIPE"
  }

As we learned earlier, connections to the ``ADMIN$`` and ``IPC$`` shares on a
target system are suspicious or malicious if they are not already authorized.

:file:`smb_files.log`
---------------------

There are many entries in the :file:`smb_files.log`. The first looks like
this:

.. literal-emph::

  {
    "ts": 1507565599.576942,
    "uid": "C6HQVsDf8VCu0XTJe",
    **"id.orig_h": "192.168.10.31",**
    "id.orig_p": 49239,
    **"id.resp_h": "192.168.10.30",**
    **"id.resp_p": 445,**
    "action": "SMB::FILE_OPEN",
    "path": "\\\\admin-pc\\ADMIN$",
    **"name": "PSEXESVC.exe",**
    "size": 0,
    "times.modified": 1507565599.607777,
    "times.accessed": 1507565599.607777,
    "times.created": 1507565599.607777,
    "times.changed": 1507565599.607777
  }

As we noted earlier, use of :file:`psexecsvc.exe` is likely malicious as
intruders use it to run :program:`PsExec` on remote systems.

We can summarize all of the entries in :file:`smb_files.log` with the following
syntax:

.. code-block:: console

  $ jq -c '[."action", ."path", ."name"]' smb_files.log

::

  ["SMB::FILE_OPEN","\\\\admin-pc\\ADMIN$","PSEXESVC.exe"]
  ["SMB::FILE_WRITE","\\\\admin-pc\\ADMIN$","PSEXESVC.exe"]
  ["SMB::FILE_WRITE","\\\\admin-pc\\ADMIN$","PSEXESVC.exe"]
  ["SMB::FILE_OPEN","\\\\admin-pc\\ADMIN$","PSEXESVC.exe"]
  ["SMB::FILE_DELETE","\\\\admin-pc\\ADMIN$","PSEXESVC.exe"]

This does not give us any more context but it shows the sorts of data in the
:file:`smb_files.log`.

:file:`extract_files/`, :file:`files.log`, and :file:`pe.log`, and VirusTotal
-----------------------------------------------------------------------------

As we did in a previous case, we can look into the files that Zeek and BZAR
captured for this activity.

The :file:`extract_files/` directory contains one executable file::

  extract_files/C6HQVsDf8VCu0XTJe_FtIFnm3ZqI1s96P74l__admin-pc_ADMIN$PSEXESVC.exe: PE32 executable (console) Intel 80386, for MS Windows

Zeek’s :file:`files.log` says the following about it:

.. literal-emph::

  {
    "ts": 1507565599.578328,
    "fuid": "FtIFnm3ZqI1s96P74l",
    "uid": "C6HQVsDf8VCu0XTJe",
    "id.orig_h": "192.168.10.31",
    "id.orig_p": 49239,
    "id.resp_h": "192.168.10.30",
    "id.resp_p": 445,
    "source": "SMB",
    "depth": 0,
    "analyzers": [
      "MD5",
      "SHA1",
      "PE",
      "EXTRACT",
      "SHA256"
    ],
    "mime_type": "application/x-dosexec",
    **"filename": "PSEXESVC.exe",**
    "duration": 0.0006651878356933594,
    "is_orig": true,
    "seen_bytes": 145568,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false,
    "md5": "75b55bb34dac9d02740b9ad6b6820360",
    "sha1": "a17c21b909c56d93d978014e63fb06926eaea8e7",
    "sha256": "141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944",
    "extracted": "C6HQVsDf8VCu0XTJe_FtIFnm3ZqI1s96P74l__admin-pc_ADMIN$PSEXESVC.exe",
    "extracted_cutoff": false
  }

Zeek’s :file:`pe.log` says the following:

.. literal-emph::

  {
    "ts": 1507565599.578328,
    "id": "FtIFnm3ZqI1s96P74l",
    "machine": "I386",
    **"compile_ts": 1467139314,**
    "os": "Windows XP",
    "subsystem": "WINDOWS_CUI",
    "is_exe": true,
    "is_64bit": false,
    "uses_aslr": true,
    "uses_dep": true,
    "uses_code_integrity": false,
    "uses_seh": true,
    "has_import_table": true,
    "has_export_table": false,
    "has_cert_table": true,
    "has_debug_data": false,
    "section_names": [
      ".text",
      ".rdata",
      ".data",
      ".rsrc",
      ".reloc"
    ]
  }

The compile time translates to human readable format as this:

.. code-block:: console

  $ date -d @1467139314

::

  Tue Jun 28 18:41:54 UTC 2016

We can also check VirusTotal using the MD5 hash:

.. code-block:: console

  $ vt file "75b55bb34dac9d02740b9ad6b6820360"

.. literal-emph::

  - _id: "141b2190f51397dbd0dfde0e3904b264c91b6f81febc823ff0c33da980b69944"
    _type: "file"
    authentihash: "62287971b29db5858ceaf92e9db310862e9082608f9dd3ac7f5ed3f71c7cfc38"
    **creation_date: 1467139314  # 2016-06-28 18:41:54 +0000 UTC**
    **first_seen_itw_date: 1463443155  # 2016-05-16 23:59:15 +0000 UTC**
    **first_submission_date: 1467293310  # 2016-06-30 13:28:30 +0000 UTC**
    **last_analysis_date: 1606108041  # 2020-11-23 05:07:21 +0000 UTC**
    last_analysis_results:
      ALYac:
        category: "undetected"
        engine_name: "ALYac"
        engine_update: "20201123"
        engine_version: "1.1.1.5"
        method: "blacklist"
  ...truncated…

The various dates for this copy of :program:`PsExecSvc` are interesting.

I am not sure how to account for a first seen in the wild date that precedes
the creation date. I think it’s interesting that only a few hours before I
worked with this sample, someone else was doing the same thing, but via
uploading the executable!

After this analysis, all we know is that :program:`PsExecSvc` is being used
successfully against ``192.168.10.31``. Mr. Marx’s paper notes that his
activity involved retrieving a file from the target. We cannot tell that from
these logs. This is an example of using Zeek logs to identify suspicious or
malicious activity, and then pivoting to host-centric data to determine exactly
what is happening.

:file:`ntlm.log`
----------------

One log we have not seen in any of these cases is the :file:`ntlm.log`. This
log captures old-style Windows NT Lan Manager (NTLM) authentication details.
The packet capture :file:`smb-on-windows-10.pcapng` provided by the Wireshark
project produces a :file:`ntlm.log` when Zeek processes it.

Ref: https://wiki.wireshark.org/SMB2

.. literal-emph::

  {
    "ts": 1476605364.033848,
    "uid": "CNicnvp8Qdqbqm96a",
    "id.orig_h": "192.168.199.133",
    "id.orig_p": 49672,
    "id.resp_h": "192.168.199.1",
    "id.resp_p": 139,
    "hostname": "DESKTOP-V1FA0UQ",
    "server_nb_computer_name": "SCV",
    "server_dns_computer_name": "SCV",
    **"success": true**
  }
  {
    "ts": 1476605590.442053,
    "uid": "CLVEN87g2bfZgXqP5",
    "id.orig_h": "192.168.199.132",
    "id.orig_p": 49670,
    "id.resp_h": "192.168.199.133",
    "id.resp_p": 445,
    "username": "user",
    "hostname": "DESKTOP-2AEFM7G",
    "domainname": "DESKTOP-2AEFM7G",
    "server_nb_computer_name": "DESKTOP-V1FA0UQ",
    "server_dns_computer_name": "DESKTOP-V1FA0UQ"
  }
  {
    "ts": 1476605590.474118,
    "uid": "C74tDzQl0ttE8v813",
    "id.orig_h": "192.168.199.132",
    "id.orig_p": 49671,
    "id.resp_h": "192.168.199.133",
    "id.resp_p": 445,
    "username": "user",
    "hostname": "DESKTOP-2AEFM7G",
    "domainname": "DESKTOP-2AEFM7G",
    "server_nb_computer_name": "DESKTOP-V1FA0UQ",
    "server_dns_computer_name": "DESKTOP-V1FA0UQ"
  }
  {
    "ts": 1476605590.484196,
    "uid": "CzLJgJ2nrXGMxvnXze",
    "id.orig_h": "192.168.199.132",
    "id.orig_p": 49672,
    "id.resp_h": "192.168.199.133",
    "id.resp_p": 445,
    "username": "user",
    "hostname": "DESKTOP-2AEFM7G",
    "domainname": "DESKTOP-2AEFM7G",
    "server_nb_computer_name": "DESKTOP-V1FA0UQ",
    "server_dns_computer_name": "DESKTOP-V1FA0UQ"
  }
  {
    "ts": 1476605590.496004,
    "uid": "Ct46uQ2dOQuqnp5YPj",
    "id.orig_h": "192.168.199.132",
    "id.orig_p": 49673,
    "id.resp_h": "192.168.199.133",
    "id.resp_p": 445,
    "username": "user",
    "hostname": "DESKTOP-2AEFM7G",
    "domainname": "DESKTOP-2AEFM7G",
    "server_nb_computer_name": "DESKTOP-V1FA0UQ",
    "server_dns_computer_name": "DESKTOP-V1FA0UQ"
  }
  {
    "ts": 1476605609.93236,
    "uid": "CQorcF2L5fLEA4EImh",
    "id.orig_h": "192.168.199.132",
    "id.orig_p": 49674,
    "id.resp_h": "192.168.199.133",
    "id.resp_p": 445,
    "username": "Tim Tester",
    "hostname": "DESKTOP-2AEFM7G",
    "domainname": "DESKTOP-2AEFM7G",
    "server_nb_computer_name": "DESKTOP-V1FA0UQ",
    "server_dns_computer_name": "DESKTOP-V1FA0UQ"
  }
  {
    "ts": 1476605761.4297,
    "uid": "CBbRT6X875vQPAgJj",
    "id.orig_h": "192.168.199.132",
    "id.orig_p": 49675,
    "id.resp_h": "192.168.199.133",
    "id.resp_p": 445,
    "username": "Willi Wireshark",
    "hostname": "DESKTOP-2AEFM7G",
    "domainname": "DESKTOP-2AEFM7G",
    "server_nb_computer_name": "DESKTOP-V1FA0UQ",
    "server_dns_computer_name": "DESKTOP-V1FA0UQ",
    **"success": true**
  }

This pcap produces a lot of Zeek logs, so I wanted to only show these entries.
Analysts would probably take two investigative steps. First, should
``192.168.199.132`` be trying to access these other systems? Second, should the
authentication have succeeded, as denoted by the two “true” results?

Conclusion
==========

This has been a large section, but the goal was to present a set of cases and
show how Zeek and BZAR (when available) made sense of them. I recommend reading
Mr. Marx’s paper for more details as well.
