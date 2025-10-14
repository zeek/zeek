=========
files.log
=========

One of Zeek’s powerful features is the ability to extract content from network
traffic and write it to disk as a file, via its
:ref:`File Analysis framework <file-analysis-framework>`. This is easiest to understand with a
protocol like File Transfer Protocol (FTP), a classic means to exchange files
over a channel separate from that used to exchange commands. Protocols like
HTTP are slightly more complicated, as it includes headers which must be
interpreted and not included in any file content transferred by the protocol.

Zeek’s :file:`files.log` is a record of files that Zeek observed while
inspecting network traffic. The existence of an entry in :file:`files.log` does
not mean that Zeek necessarily extracted file content and wrote it to disk.
Analysts must configure Zeek to extract files by type in order to have them
written to disk.

In the following example, an analyst has configured Zeek to extract files of
MIME type ``application/x-dosexec`` and write them to disk. To understand the
chain of events that result in having a file on disk, we will start with the
conn.log, progress to the :file:`http.log`, and conclude with the :file:`files.log`.

The Zeek scripting manual, derived from the Zeek source code, completely
explains the meaning of each field in the :file:`files.log` (and other logs).
It would be duplicative to manually recreate that information in another format
here.  Therefore, this entry seeks to show how an analyst would make use of the
information in the :file:`files.log`. Those interested in getting details on
every element of the :file:`files.log` should refer to :zeek:see:`Files::Info`.

Throughout the sections that follow, we will inspect Zeek logs in JSON format.
As we have shown how to access logs like this previously using the command
line, we will only show the log entries themselves.

Inspecting the :file:`conn.log`
===============================

The log with which we begin our analysis for this case is the :file:`conn.log`.
It contains the following entry of interest.

.. literal-emph::

  {
    "ts": 1596820191.94147,
    **"uid": "CzoFRWTQ6YIzfFXHk"**,
    **"id.orig_h": "192.168.4.37",**
    "id.orig_p": 58264,
    **"id.resp_h": "23.195.64.241",**
    **"id.resp_p": 80,**
    "proto": "tcp",
    **"service": "http",**
    "duration": 0.050640106201171875,
    "orig_bytes": 211,
    "resp_bytes": 179604,
    "conn_state": "SF",
    "missed_bytes": 0,
    "history": "ShADadtFf",
    "orig_pkts": 93,
    "orig_ip_bytes": 5091,
    "resp_pkts": 129,
    "resp_ip_bytes": 186320
  }

We see that ``192.168.4.37`` contacted ``23.195.64.241`` via HTTP and connected
to port 80 TCP. The responder sent 179604 bytes of data during the
conversation.

Because this conversation appears to have taken place using HTTP, a clear text
protocol, there is a good chance that we can directly inspect the HTTP headers
and the payloads that were exchanged.

We will use the UID, ``CzoFRWTQ6YIzfFXHk``, to find corresponding entries in
other log sources to better understand what happened during this conversation.

Inspecting the :file:`http.log`
===============================

We search our :file:`http.log` files for samples containing the UID of interest
and find the following entry:

.. literal-emph::

  {
    "ts": 1596820191.94812,
    **"uid": "CzoFRWTQ6YIzfFXHk",**
    "id.orig_h": "192.168.4.37",
    "id.orig_p": 58264,
    "id.resp_h": "23.195.64.241",
    "id.resp_p": 80,
    "trans_depth": 1,
    **"method": "GET",**
    **"host": "download.microsoft.com",**
    **"uri": "/download/d/e/5/de5351d6-4463-4cc3-a27c-3e2274263c43/wfetch.exe",**
    "version": "1.1",
    **"user_agent": "Wget/1.19.4 (linux-gnu)",**
    "request_body_len": 0,
    "response_body_len": 179272,
    **"status_code": 200,**
    **"status_msg": "OK",**
    "tags": [],
    "resp_fuids": [
      **"FBbQxG1GXLXgmWhbk9"**
    ],
    "resp_mime_types": [
      **"application/x-dosexec"**
    ]
  }

The most interesting elements of this log entry include the following::

  "method": "GET",
  "host": "download.microsoft.com",
  "uri": "/download/d/e/5/de5351d6-4463-4cc3-a27c-3e2274263c43/wfetch.exe",

This shows us what file the client was trying to retrieve, ``wfetch.exe``,
from what site, ``download.microsoft.com``.

The following element shows us the client that made the request::

  "user_agent": "Wget/1.19.4 (linux-gnu)",

According to this log entry, the user agent was not a Microsoft product, but
was a Linux version of the :program:`wget` utility. User agent fields can be
manipulated, so we cannot trust that this was exactly what happened. It is
probable however that :program:`wget` was used in this case.

The following entry shows us that the Web server responding positively to the
request::

  "status_code": 200,
  "status_msg": "OK",

Based on this entry and the amount of bytes transferred, it is likely that the
client received the file it requested.

The final two entries of interest tell us something more about the content that
was transferred and how to locate it::

  "resp_fuids": [
    "FBbQxG1GXLXgmWhbk9"
  ],
  "resp_mime_types": [
    "application/x-dosexec"

The first entry provides a file identifier. This is similar to the connection
identifier in the :file:`conn.log`, except that we use the file identifier to
locate specific file contents when written to disk.

The second entry shows that Zeek recognized the file content as
``application/x-dosexec``, which likely means that the client retrieved a
Windows executable file.

Inspecting the :file:`files.log`
================================

Armed with the file identifier value, we can search any of our
:file:`files.log` repositories for matching values. By searching for the FUID
of ``FBbQxG1GXLXgmWhbk9`` we find the following entry.

.. literal-emph::

  {
    "ts": 1596820191.969902,
    **"fuid": "FBbQxG1GXLXgmWhbk9",**
    "uid": "CzoFRWTQ6YIzfFXHk",
    "id.orig_h": "192.168.4.37",
    "id.orig_p": 58264,
    "id.resp_h": "23.195.64.241",
    "id.resp_p": 80,
    "source": "HTTP",
    "depth": 0,
    "analyzers": [
      "EXTRACT",
      "PE"
    ],
    **"mime_type": "application/x-dosexec",**
    "duration": 0.015498876571655273,
    "is_orig": false,
    "seen_bytes": 179272,
    "total_bytes": 179272,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false,
    **"extracted": "HTTP-FBbQxG1GXLXgmWhbk9.exe",**
    "extracted_cutoff": false
  }

Note that this :file:`files.log` entry also contains the UID we found in the
:file:`conn.log`, e.g., ``CzoFRWTQ6YIzfFXHk``. Theoretically we could have just
searched for that UID value and not bothered to locate the FUID in the
:file:`http.log`.  However, I find that it makes sense to follow this sort of
progression, as we cannot rely on this same analytical workflow for all cases.

In this :file:`files.log` data, we see that the ``EXTRACT`` and ``PE`` analyzer
events were activated. Zeek saw 179272 bytes transferred and does not appear to
have missed any bytes. Zeek extracted the file it saw as
``HTTP-FBbQxG1GXLXgmWhbk9.exe``, which means we should be able to locate that
file on disk.

The ``is_orig`` field in a :file:`files.log` entry can be used to determine
which endpoint sent the file. When ``is_orig`` is ``false``, the responder of
the connection is sending the file. In the example above we can tell that
the HTTP server at ``23.195.64.241`` is sending the file and ``192.168.4.37``
is receiving it.

Inspecting the Extracted File
=============================

The location for extracted files will vary depending on your Zeek
configuration. In my example, Zeek wrote extracted files to a directory called
:file:`extract_files/`. Here is the file in question:

.. code-block:: console

  $ ls -al HTTP-FBbQxG1GXLXgmWhbk9.exe

::

  -rw-rw-r-- 1 zeek zeek 179272 Aug  7 17:23 HTTP-FBbQxG1GXLXgmWhbk9.exe

Note the byte count, 179272, matches the value in the :file:`files.log`.

Here is what the Linux file command thinks of this file.

.. code-block:: console

  $ file HTTP-FBbQxG1GXLXgmWhbk9.exe

::

  HTTP-FBbQxG1GXLXgmWhbk9.exe: PE32 executable (GUI) Intel 80386, for MS Windows, MS CAB-Installer self-extracting archive

This looks like a Windows executable. You can use the :program:`md5sum` utility to
generate a MD5 hash of the file.

.. code-block:: console

  $ md5sum HTTP-FBbQxG1GXLXgmWhbk9.exe

::

  6711727adf76599bf50c9426057a35fe  HTTP-FBbQxG1GXLXgmWhbk9.exe

We can search by the hash value on VirusTotal using the :program:`vt` command
line tool, provided we have registered and initialized :program:`vt` with our
free API key.

.. code-block:: console

  $ ./vt file 6711727adf76599bf50c9426057a35fe

::

  - _id: "82f39086658ce80df4da6a49fef9d3062a00fd5795a4dd5042de32907bcb5b89"
    _type: "file"
    authentihash: "2a07d356273d32bf0c5aff83ea847351128fc3971b44052f92b6fb4f45c2272f"
    creation_date: 1030609542  # 2002-08-29 08:25:42 +0000 UTC
    first_submission_date: 1354191312  # 2012-11-29 12:15:12 +0000 UTC
    last_analysis_date: 1592215708  # 2020-06-15 10:08:28 +0000 UTC
    last_analysis_results:
      ALYac:
        category: "undetected"
        engine_name: "ALYac"
        engine_update: "20200615"
        engine_version: "1.1.1.5"
        method: "blacklist"
  ...edited…
   last_analysis_stats:
      confirmed-timeout: 0
      failure: 0
      harmless: 0
      malicious: 0
      suspicious: 0
      timeout: 0
      type-unsupported: 2
      undetected: 74
    last_modification_date: 1592220693  # 2020-06-15 11:31:33 +0000 UTC
    last_submission_date: 1539056691  # 2018-10-09 03:44:51 +0000 UTC
    magic: "PE32 executable for MS Windows (GUI) Intel 80386 32-bit"
    md5: "6711727adf76599bf50c9426057a35fe"
    meaningful_name: "WEXTRACT.EXE"
    names:
    - "Wextract"
    - "WEXTRACT.EXE"
    - "wfetch.exe"
    - "583526"
    packers:
      F-PROT: "CAB, ZIP"
      PEiD: "Microsoft Visual C++ v6.0 SPx"
    pe_info:
      entry_point: 23268
      imphash: "1494de9b53e05fc1f40cb92afbdd6ce4"
      import_list:
      - imported_functions:
        - "GetLastError"
        - "IsDBCSLeadByte"
        - "DosDateTimeToFileTime"
        - "ReadFile"
        - "GetStartupInfoA"
        - "GetSystemInfo"
        - "lstrlenA"
  ...edited...
   size: 179272
    ssdeep: "3072:BydJq5oyVzs+h0Jk5irDStDD5QOsP0CLRQq8ZZ3xlf/AQnFlFuKIUaKJH:UW2+AiDWOsPxQq8HHf/A07namH"
    tags:
    - "invalid-signature"
    - "peexe"
    - "signed"
    - "overlay"
    times_submitted: 33
    total_votes:
      harmless: 1
      malicious: 0
    trid:
    - file_type: "Microsoft Update - Self Extracting Cabinet"
      probability: 46.3
    - file_type: "Win32 MS Cabinet Self-Extractor (WExtract stub)"
      probability: 41.4
    - file_type: "Win32 Executable MS Visual C++ (generic)"
      probability: 4.2
    - file_type: "Win64 Executable (generic)"
      probability: 3.7
    - file_type: "Win16 NE executable (generic)"
      probability: 1.9
    type_description: "Win32 EXE"
    type_tag: "peexe"
    unique_sources: 24
    vhash: "  size: 179272
    ssdeep: "3072:BydJq5oyVzs+h0Jk5irDStDD5QOsP0CLRQq8ZZ3xlf/AQnFlFuKIUaKJH:UW2+AiDWOsPxQq8HHf/A07namH"
    tags:
    - "invalid-signature"
    - "peexe"
    - "signed"
    - "overlay"
    times_submitted: 33
    total_votes:
      harmless: 1
      malicious: 0
    trid:
    - file_type: "Microsoft Update - Self Extracting Cabinet"
      probability: 46.3
    - file_type: "Win32 MS Cabinet Self-Extractor (WExtract stub)"
      probability: 41.4
    - file_type: "Win32 Executable MS Visual C++ (generic)"
      probability: 4.2
    - file_type: "Win64 Executable (generic)"
      probability: 3.7
    - file_type: "Win16 NE executable (generic)"
      probability: 1.9
    type_description: "Win32 EXE"
    type_tag: "peexe"
    unique_sources: 24
    vhash: "0150366d1570e013z1004cmz1f03dz"

You can access the entire report `via the Web here
<https://www.virustotal.com/gui/file/82f39086658ce80df4da6a49fef9d3062a00fd5795a4dd5042de32907bcb5b89/detection>`_.

It appears this is a harmless Windows executable. However, by virtue of having
it extracted from network traffic, analysts have many options for investigation
when the file is not considered benign.

Conclusion
==========

Zeek’s file extraction capabilities offer many advantages to analysts.
Administrators can configure Zeek to compute MD5 hashes of files that Zeek sees
in network traffic. Rather than computing a hash on a file written to disk,
Zeek could simply compute the hash as part of its inspection process. The
purpose of this document was to show some of the data in the :file:`files.log`,
how it relates to other Zeek logs, and how analysts might make use of it.
