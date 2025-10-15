======
pe.log
======

Earlier we looked at the data provided by Zeek’s :file:`files.log`. In this
section we will take a step further for one type of log -- Zeek’s
:file:`pe.log`. In this instance, “pe” stands for portable executable, a format
associated with Microsoft binaries.

For more details on the specifics of the format, please refer to
:zeek:see:`PE::Info`.

Starting with :file:`conn.log`
==============================

This example starts with the :file:`conn.log`. It’s not strictly necessary to
explain the :file:`pe.log`, although I wanted to include a very recent example
of a modern application conducting activities via HTTP.

.. literal-emph::

  {
    "ts": "2020-09-23T00:24:31.210053Z",
    "uid": "Cq2b9jR12c4lqZafg",
    **"id.orig_h": "192.168.4.152",**
    "id.orig_p": 59125,
    **"id.resp_h": "63.88.73.83",**
    **"id.resp_p": 80,**
    "proto": "tcp",
    **"service": "http",**
    "duration": 25.614583015441895,
    "orig_bytes": 5753,
    "resp_bytes": 1975717,
    "conn_state": "SF",
    "local_orig": true,
    "local_resp": false,
    "missed_bytes": 0,
    "history": "ShADadttFf",
    "orig_pkts": 521,
    "orig_ip_bytes": 29041,
    "resp_pkts": 1367,
    "resp_ip_bytes": 2030409,
  }

This example shows a host, ``192.168.4.152``, conducting a HTTP session with
``63.88.73.83`` over port 80 TCP. The server sends 2 MB of content to the
client.

Continuing with :file:`http.log`
================================

The :file:`http.log` entries associated with UID ``Cq2b9jR12c4lqZafg`` are
fascinating. There are multiple entries. I have reproduced a sample of them
below.

.. literal-emph::

  {
    "ts": "2020-09-23T00:24:31.235201Z",
    "uid": "Cq2b9jR12c4lqZafg",
    **"id.orig_h": "192.168.4.152",**
    "id.orig_p": 59125,
    **"id.resp_h": "63.88.73.83",**
    **"id.resp_p": 80,**
    "trans_depth": 1,
    **"method": "HEAD",**
    **"host": "r8---sn-8xgp1vo-p5ql.gvt1.com",**
    **"uri": "/edgedl/release2/chrome/SAWXCyZhLAbPfxC5kv_Fkw_85.0.4183.121/85.0.4183.121_85.0.4183.102_chrome_updater.exe?cms_redirect=yes&mh=t-&mip=-public-ip-edited-&mm=28&mn=sn-8xgp1vo-p5ql&ms=nvh&mt=1600820539&mv=m&mvi=8&pl=19&shardbypass=yes",**
    "version": "1.1",
    **"user_agent": "Microsoft BITS/7.8",**
    "request_body_len": 0,
    "response_body_len": 0,
    **"status_code": 200,**
    **"status_msg": "OK",**
    "tags": []
  }

The first entry shown above provides details on a HEAD request for a binary
titled ``85.0.4183.121_85.0.4183.102_chrome_updater.exe``. The user agent is
the Microsoft Background Intelligent Transfer Service (BITS). The server
responses with a successful message, 200 OK. Note that I have inserted
``-public-ip-edited-`` in the URI rather than expose the public IP address of
the system requesting this file.

The fact that the BITS client provides the public IP address in the URI
indicates that either the server is sending this information to the client, or
that the client is requesting this information from an Internet-residing
system. There is no native way for this client to know its public IP address
when it is sitting behind a network address (port) translation device.

This aspect of the URI could help administrators better understand their
networks, as it can sometimes be difficult to map private IP addresses (like
``192.168.4.152``) to their public representations (here
``-public-ip-edited-``).

Also note the value for the host field showing
``r8---sn-8xgp1vo-p5ql.gvt1.com``. I resolved the odd name to see the
following:

.. code-block:: console

  $ host r8---sn-8xgp1vo-p5ql.gvt1.com

::

  r8---sn-8xgp1vo-p5ql.gvt1.com is an alias for r8.sn-8xgp1vo-p5ql.gvt1.com.
  r8.sn-8xgp1vo-p5ql.gvt1.com has address 63.88.73.83
  r8.sn-8xgp1vo-p5ql.gvt1.com has IPv6 address 2600:803:f00:1::13

Let’s look at the next :file:`http.log` entry.

.. literal-emph::

  {
    "ts": "2020-09-23T00:24:31.334435Z",
    "uid": "Cq2b9jR12c4lqZafg",
    **"id.orig_h": "192.168.4.152",**
    "id.orig_p": 59125,
    **"id.resp_h": "63.88.73.83",**
    **"id.resp_p": 80,**
    "trans_depth": 2,
    **"method": "GET",**
    **"host": "r8---sn-8xgp1vo-p5ql.gvt1.com",**
    **"uri": "/edgedl/release2/chrome/SAWXCyZhLAbPfxC5kv_Fkw_85.0.4183.121/85.0.4183.121_85.0.4183.102_chrome_updater.exe?cms_redirect=yes&mh=t-&mip=-public-ip-edited-&mm=28&mn=sn-8xgp1vo-p5ql&ms=nvh&mt=1600820539&mv=m&mvi=8&pl=19&shardbypass=yes",**
    "version": "1.1",
    **"user_agent": "Microsoft BITS/7.8",**
    "request_body_len": 0,
    "response_body_len": 1392,
    **"status_code": 206,**
    **"status_msg": "Partial Content",**
    "tags": [],
    "resp_fuids": [
      **"FGYKX64SkXc4OcvlFf"**
    ]
  }

In the previous :file:`http.log` entry we see that the BITS client has made a
GET request for the same file. The server is providing it via “partial
content”, represented by the 206 status code.

Also note we now have a file UID present in the :file:`http.log`:
``FGYKX64SkXc4OcvlFf``.

The next :file:`http.log` entry is similar, although the amount of data sent is
different.

.. literal-emph::

  {
    "ts": "2020-09-23T00:24:35.247333Z",
    "uid": "Cq2b9jR12c4lqZafg",
    "id.orig_h": "192.168.4.152",
    "id.orig_p": 59125,
    "id.resp_h": "63.88.73.83",
    "id.resp_p": 80,
    "trans_depth": 3,
    "method": "GET",
    "host": "r8---sn-8xgp1vo-p5ql.gvt1.com",
    "uri": "/edgedl/release2/chrome/SAWXCyZhLAbPfxC5kv_Fkw_85.0.4183.121/85.0.4183.121_85.0.4183.102_chrome_updater.exe?cms_redirect=yes&mh=t-&mip=-public-ip-edited-&mm=28&mn=sn-8xgp1vo-p5ql&ms=nvh&mt=1600820539&mv=m&mvi=8&pl=19&shardbypass=yes",
    "version": "1.1",
    "user_agent": "Microsoft BITS/7.8",
    "request_body_len": 0,
    **"response_body_len": 1995,**
    "status_code": 206,
    "status_msg": "Partial Content",
    "tags": []
  }

I have removed the half a dozen or so intervening messages as they are very
similar to the preceding entries. I include the last one for reference. It is
similar to the previous entries, although the response body length shows much
more data was sent.

.. literal-emph::

  {
    "ts": "2020-09-23T00:24:46.547359Z",
    "uid": "Cq2b9jR12c4lqZafg",
    "id.orig_h": "192.168.4.152",
    "id.orig_p": 59125,
    "id.resp_h": "63.88.73.83",
    "id.resp_p": 80,
    "trans_depth": 12,
    "method": "GET",
    "host": "r8---sn-8xgp1vo-p5ql.gvt1.com",
    "uri": "/edgedl/release2/chrome/SAWXCyZhLAbPfxC5kv_Fkw_85.0.4183.121/85.0.4183.121_85.0.4183.102_chrome_updater.exe?cms_redirect=yes&mh=t-&mip=-public-ip-edited-&mm=28&mn=sn-8xgp1vo-p5ql&ms=nvh&mt=1600820539&mv=m&mvi=8&pl=19&shardbypass=yes",
    "version": "1.1",
    "user_agent": "Microsoft BITS/7.8",
    "request_body_len": 0,
    **"response_body_len": 652148,**
    "status_code": 206,
    "status_msg": "Partial Content",
    "tags": []
  }

That concludes the relevant :file:`http.log` entries. Using the file UID we can
search the :file:`files.log` next.

Continuing with :file:`files.log`
=================================

The relevant :file:`files.log` entry contains the following:

.. literal-emph::

  {
    "ts": "2020-09-23T00:24:31.334435Z",
    "fuid": "FGYKX64SkXc4OcvlFf",
    "uid": "Cq2b9jR12c4lqZafg",
    "id.orig_h": "192.168.4.152",
    "id.orig_p": 59125,
    "id.resp_h": "63.88.73.83",
    "id.resp_p": 80,
    **"source": "HTTP",**
    "depth": 0,
    "analyzers": [
      "MD5",
      **"PE",**
      "SHA1",
      "EXTRACT"
    ],
    **"mime_type": "application/x-dosexec",**
    "duration": 15.468528032302856,
    "local_orig": false,
    "is_orig": false,
    "seen_bytes": 1967360,
    "total_bytes": 1967360,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false,
    **"md5": "a5843bd951f148e99b7265e5bd159fb7",**
    "sha1": "fc8b8deb5b34fec1f3f094e579667b2bddee0b21",
    **"extracted": "/nsm/zeek/extracted/HTTP-FGYKX64SkXc4OcvlFf.exe",**
    "extracted_cutoff": false
  }

This :file:`files.log` entry shows that the content returned by the BITS server
included a Windows executable. Zeek calculates MD5 and SHA1 hashes, and also
shows the location on disk for the extracted file.

Do you remember a similar entry from the Zeek documentation on
:file:`files.log`?

::

  "analyzers": [
      "EXTRACT",
      "PE"
    ],

In that example, we have active extract and PE analyzers.

In the current :file:`files.log`, we have additional analyzers present:

.. literal-emph::

  "analyzers": [
    "MD5",
    **"PE",**
    "SHA1",
    "EXTRACT"
  ],

Thanks to these analyzers, we have the MD5 and SHA1 hashes, along with a
:file:`pe.log` entry and an extracted file.

Continuing with :file:`pe.log`
==============================

Finally we come to the :file:`pe.log`. We are able to connect it with the
appropriate activity using the file UID ``FGYKX64SkXc4OcvlFf``.

.. literal-emph::

  {
    "ts": "2020-09-23T00:24:36.395445Z",
    **"id": "FGYKX64SkXc4OcvlFf",**
    "machine": "AMD64",
    **"compile_ts": "2020-09-19T00:10:08.000000Z",**
    **"os": "Windows XP x64 or Server 2003",**
    **"subsystem": "WINDOWS_GUI",**
    **"is_exe": true,**
    **"is_64bit": true,**
    "uses_aslr": true,
    "uses_dep": true,
    "uses_code_integrity": false,
    "uses_seh": true,
    "has_import_table": true,
    "has_export_table": false,
    "has_cert_table": true,
    "has_debug_data": true,
    "section_names": [
      ".text",
      ".rdata",
      ".data",
      ".pdata",
      ".00cfg",
      ".rsrc",
      ".reloc"
    ]
  }

The compile time is one of the more interesting details for analysts. This is a
freshly compiled Windows executable.

Reviewing the Extracted Binary
==============================

As we did in the :file:`files.log` documentation, we can analyze our extracted
file using the command line version of VirusTotal.

Here is the extracted file on disk. Notice the filename includes the file UID
calculated by Zeek, i.e., ``FGYKX64SkXc4OcvlFf``.

.. code-block:: console

  $ file /nsm/zeek/extracted/HTTP-FGYKX64SkXc4OcvlFf.exe

::

  /nsm/zeek/extracted/HTTP-FGYKX64SkXc4OcvlFf.exe: PE32+ executable (GUI) x86-64, for MS Windows

We use the Linux :program:`md5sum` utility to calculate the MD5 hash.

.. code-block:: console

  $ md5sum /nsm/zeek/extracted/HTTP-FGYKX64SkXc4OcvlFf.exe

::

  a5843bd951f148e99b7265e5bd159fb7  /nsm/zeek/extracted/HTTP-FGYKX64SkXc4OcvlFf.exe

Note the MD5 hash matches the one provided by Zeek in the :file:`files.log`
entry.

Next we submit the hash, not the binary, to VirusTotal for analysis. Whenever
possible, submit hashes to cloud file analysis engines. This preserves the
confidentiality of your sample.

The output is edited for readability.

.. code-block:: console

  $ vt file a5843bd951f148e99b7265e5bd159fb7

.. literal-emph::

  - _id: "14a1b9947b77174244a6f6bfd2cd7e1b1c860a09b3b5d74f07b81e45b5548de4"
    _type: "file"
    authentihash: "a4a6a1011bb3e33af37a1dce19bd41b72d5360dc4175d570ec7260d1d9815747"
    **creation_date: 1600474208  # 2020-09-19 00:10:08 +0000 UTC**
    **first_submission_date: 1600711798  # 2020-09-21 18:09:58 +0000 UTC**
    **last_analysis_date: 1600840562  # 2020-09-23 05:56:02 +0000 UTC**
    last_analysis_results:
      ALYac:
        category: "undetected"
        engine_name: "ALYac"
        engine_update: "20200923"
        engine_version: "1.1.1.5"
        method: "blacklist"
     ...edited...
      eGambit:
        category: "undetected"
        engine_name: "eGambit"
        engine_update: "20200923"
        method: "blacklist"
    last_analysis_stats:
      confirmed-timeout: 0
      failure: 0
      harmless: 0
      malicious: 0
      suspicious: 0
      timeout: 0
      type-unsupported: 4
      undetected: 69
    last_modification_date: 1600878930  # 2020-09-23 16:35:30 +0000 UTC
    last_submission_date: 1600830769  # 2020-09-23 03:12:49 +0000 UTC
    magic: "PE32+ executable for MS Windows (GUI) Mono/.Net assembly"
    md5: "a5843bd951f148e99b7265e5bd159fb7"
    **meaningful_name: "mini_installer"**
    names:
    **- "85.0.4183.121_85.0.4183.102_chrome_updater.exe"**
    - "mini_installer"
    **- "HTTP-FjcOYuaXbbQFV1cJj.exe"**
    pe_info:
      entry_point: 4096
      imphash: "ec06ab323a50409817b4a6a54b98f157"
      import_list:
      - imported_functions:
        - "CommandLineToArgvW"
        library_name: "SHELL32.dll"
      - imported_functions:
        - "GetLastError"
        - "GetVolumePathNameW"
     ...edited...
        - "GetEnvironmentVariableW"
        library_name: "KERNEL32.dll"
      machine_type: 34404
      overlay:
        chi2: 1124223.375
        entropy: 4.492208003997803
        filetype: "binary Computer Graphics Metafile"
        md5: "ddc7adbbc3760a81d8510e57fedbe055"
        offset: 1951232
        size: 16128
      resource_details:
      - chi2: 286.0988464355469
        entropy: 7.999892711639404
        filetype: "Data"
        lang: "ENGLISH US"
        sha256: "133ccfebc6cebb05333ed1677bb419716a8ad00b39417f2f4fa6ee45bdbb92df"
        type: "B7"
    ...edited...
      timestamp: 1600474208
    reputation: 0
    sha1: "fc8b8deb5b34fec1f3f094e579667b2bddee0b21"
    sha256: "14a1b9947b77174244a6f6bfd2cd7e1b1c860a09b3b5d74f07b81e45b5548de4"
    signature_info:
      copyright: "Copyright 2020 Google LLC. All rights reserved."
      counter signers: "TIMESTAMP-SHA256-2019-10-15; DigiCert SHA2 Assured ID Timestamping CA; DigiCert"
      counter signers details:
      - algorithm: "sha256RSA"
        cert issuer: "DigiCert SHA2 Assured ID Timestamping CA"
        name: "TIMESTAMP-SHA256-2019-10-15"
        serial number: "04 CD 3F 85 68 AE 76 C6 1B B0 FE 71 60 CC A7 6D"
        status: "Valid"
        thumbprint: "0325BD505EDA96302DC22F4FA01E4C28BE2834C5"
        valid from: "12:00 AM 10/01/2019"
        valid to: "12:00 AM 10/17/2030"
        valid usage: "Timestamp Signing"
      - algorithm: "sha256RSA"
        cert issuer: "DigiCert Assured ID Root CA"
        name: "DigiCert SHA2 Assured ID Timestamping CA"
        serial number: "0A A1 25 D6 D6 32 1B 7E 41 E4 05 DA 36 97 C2 15"
        status: "Valid"
        thumbprint: "3BA63A6E4841355772DEBEF9CDCF4D5AF353A297"
        valid from: "12:00 PM 01/07/2016"
        valid to: "12:00 PM 01/07/2031"
        valid usage: "Timestamp Signing"
      - algorithm: "sha1RSA"
        cert issuer: "DigiCert Assured ID Root CA"
        name: "DigiCert"
        serial number: "0C E7 E0 E5 17 D8 46 FE 8F E5 60 FC 1B F0 30 39"
        status: "Valid"
        thumbprint: "0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43"
        valid from: "12:00 AM 11/10/2006"
        valid to: "12:00 AM 11/10/2031"
        valid usage: "Client Auth, Code Signing, Email Protection, Server Auth, Timestamp Signing"
      **description: "Google Chrome Installer"**
      **file version: "85.0.4183.121"**
      **internal name: "mini_installer"**
      **product: "Google Chrome Installer"**
      signers: "Google LLC; DigiCert SHA2 Assured ID Code Signing CA; DigiCert"
      signers details:
      - algorithm: "sha256RSA"
        cert issuer: "DigiCert SHA2 Assured ID Code Signing CA"
        name: "Google LLC"
        serial number: "0C 15 BE 4A 15 BB 09 03 C9 01 B1 D6 C2 65 30 2F"
        status: "Valid"
        thumbprint: "CB7E84887F3C6015FE7EDFB4F8F36DF7DC10590E"
        valid from: "12:00 AM 11/07/2018"
        valid to: "12:00 PM 11/17/2021"
        valid usage: "Code Signing"
      ...edited...
    ssdeep: "49152:zS2WLLoAgkZlbpkJDy5KrwM4wN9UT90hZv6AFV56vt9IWA:m2WvgSbpkFAKrwMpTZJV5kgW"
    tags:
    - "peexe"
    - "assembly"
    - "overlay"
    - "runtime-modules"
    - "signed"
    - "64bits"
    - "trusted"
    times_submitted: 2
    total_votes:
      harmless: 0
      malicious: 0
    trid:
    - file_type: "OS/2 Executable (generic)"
      probability: 33.6
    - file_type: "Generic Win/DOS Executable"
      probability: 33.1
    - file_type: "DOS Executable Generic"
      probability: 33.1
    **trusted_verdict:**
      **filename: "85.0.4183.121_85.0.4183.102_chrome_updater.exe"**
      **link: "https://dl.google.com/dl/release2/chrome/SAWXCyZhLAbPfxC5kv_Fkw_85.0.4183.121/85.0.4183.121_85.0.4183.102_chrome_updater.exe"**
      **organization: "Google"**
      **verdict: "goodware"**
    type_description: "Win32 EXE"
    type_tag: "peexe"
    unique_sources: 2
    vhash: "016076651d151515751az36hz1lz"

This file appears to be a component of the Google Chrome Installer. It is not
malicious software.

Conclusion
==========

Although the :file:`pe.log` was only part of this section, I wanted to show an
integrated set of Zeek logs for this example, beginning with the
:file:`conn.log`, continuing with the :file:`http.log` and :file:`files.log`,
and concluding with the :file:`pe.log`.  This is recent activity and shows that
modern software still uses HTTP in some cases!
