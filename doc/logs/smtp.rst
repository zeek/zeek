========
smtp.log
========

In the section discussing the :file:`http.log`, we noted that most HTTP traffic
is now encrypted and transmitted as HTTPS. We face a similar situation with
Simple Mail Transfer Protocol (SMTP). For a protocol with “simple” in its name,
modern instantiations of SMTP are surprisingly complex.

For the purpose of this article, it’s sufficient to recognize that a mail user
agent (MUA) seeking to submit email via SMTP will contact a mail submission
agent (MSA). Modern implementations will use ports 587 or 465 TCP, which is
encrypted using TLS. Unencrypted implementations will use port 25 TCP.

Because SMTP traffic on ports 587 or 465 TCP is encrypted, we will not see
individual emails when observing traffic using those protocols. This section
will demonstrate how Zeek reports on email traffic using ports 25, 465, and 587
TCP.

Remember that to see the meaning of each field in the :file:`smtp.log`, check
:zeek:see:`SMTP::Info`.

Inspecting SMTP Traffic
=======================

The following is a capture of an SMTP session retrieved from an online packet
capture database. I have reconstructed the session using :program:`tcpflow` and
edited it to remove material not necessary to make my point.

.. literal-emph::

  SMTP server: 220-xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500
  220-We do not authorize the use of this system to transport unsolicited,
  220 and/or bulk e-mail.

  SMTP client: **EHLO GP**

  SMTP server: 250-xc90.websitewelcome.com Hello GP [122.162.143.157]
  250-SIZE 52428800
  250-PIPELINING
  250-AUTH PLAIN LOGIN
  250-STARTTLS
  250 HELP

  SMTP client: **AUTH LOGIN**

  SMTP server: 334 VXNlcm5hbWU6

  SMTP client: **Z3VycGFydGFwQHBhdHJpb3RzLmlu**

  SMTP server: 334 UGFzc3dvcmQ6

  SMTP client: **cHVuamFiQDEyMw==**

  SMTP server: 235 Authentication succeeded

  SMTP client: **MAIL FROM: <gurpartap@patriots.in>**

  SMTP server: 250 OK

  SMTP client: **RCPT TO: <raj_deol2002in@yahoo.co.in>**

  SMTP server: 250 Accepted

  SMTP client: **DATA**

  SMTP server: 354 Enter message, ending with "." on a line by itself

  SMTP client: **From: "Gurpartap Singh" <gurpartap@patriots.in>**
  **To: <raj_deol2002in@yahoo.co.in>**
  **Subject: SMTP**
  **Date: Mon, 5 Oct 2009 11:36:07 +0530**
  **Message-ID: <000301ca4581$ef9e57f0$cedb07d0$@in>**
  **MIME-Version: 1.0**
  **Content-Type: multipart/mixed;**
  **.boundary="----=_NextPart_000_0004_01CA45B0.095693F0"**
  **X-Mailer: Microsoft Office Outlook 12.0**
  **Thread-Index: AcpFgem9BvjjZEDeR1Kh8i+hUyVo0A==**
  **Content-Language: en-us**
  **x-cr-hashedpuzzle: SeA= AAR2 ADaH BpiO C4G1 D1gW FNB1 FPkR Fn+W HFCP HnYJ JO7s Kum6 KytW LFcI LjUt;1;cgBhAGoAXwBkAGUAbwBsADIAMAAwADIAaQBuAEAAeQBhAGgAbwBvAC4AYwBvAC4AaQBuAA==;Sosha1_v1;7;{CAA37F59-1850-45C7-8540-AA27696B5398};ZwB1AHIAcABhAHIAdABhAHAAQABwAGEAdAByAGkAbwB0AHMALgBpAG4A;Mon, 05 Oct 2009 06:06:01 GMT;UwBNAFQAUAA=**
  **x-cr-puzzleid: {CAA37F59-1850-45C7-8540-AA27696B5398}**

  **This is a multipart message in MIME format.**

  **------=_NextPart_000_0004_01CA45B0.095693F0**
  **Content-Type: multipart/alternative;**
  **.boundary="----=_NextPart_001_0005_01CA45B0.095693F0"**


  **------=_NextPart_001_0005_01CA45B0.095693F0**
  **Content-Type: text/plain;**
  **.charset="us-ascii"**
  **Content-Transfer-Encoding: 7bit**

  **Hello**



  **I send u smtp pcap file**

  **Find the attachment**



  **GPS**


  **------=_NextPart_001_0005_01CA45B0.095693F0**
  **Content-Type: text/html;**
  **.charset="us-ascii"**
  **Content-Transfer-Encoding: quoted-printable**

  **<html xmlns:v=3D"urn:schemas-microsoft-com:vml" =**
  **xmlns:o=3D"urn:schemas-microsoft-com:office:office" =**
  **xmlns:w=3D"urn:schemas-microso**
  **SMTP client: ft-com:office:word" =**
  **xmlns:m=3D"http://schemas.microsoft.com/office/2004/12/omml" =**
  **xmlns=3D"http://www.w3.org/TR/REC-html40">**

  **<head>**
  **<META HTTP-EQUIV=3D"Content-Type" CONTENT=3D"text/html; =**
  **charset=3Dus-ascii">**
  **<meta name=3DGenerator content=3D"Microsoft Word 12 (filtered medium)">**
  **<style>**
  **<!--**
  ** /* Font Definitions */**
  ** @font-face**
  **...edited...**
  **  <o:idmap v:ext=3D"edit" data=3D"1" />**
  ** </o:shapelayout></xml><![endif]-->**
  **</head>**

  **<body lang=3DEN-US link=3Dblue vlink=3Dpurple>**

  **<div class=3DSection1>**
  SMTP client:

  **<p class=3DMsoNormal>Hello<o:p></o:p></p>**

  **<p class=3DMsoNormal><o:p>&nbsp;</o:p></p>**

  **<p class=3DMsoNormal>I send u smtp pcap file <o:p></o:p></p>**

  **<p class=3DMsoNormal>Find the attachment<o:p></o:p></p>**

  **<p class=3DMsoNormal><o:p>&nbsp;</o:p></p>**

  **<p class=3DMsoNormal>GPS<o:p></o:p></p>**

  **</div>**

  **</body>**

  **</html>**

  **------=_NextPart_001_0005_01CA45B0.095693F0--**

  **------=_NextPart_000_0004_01CA45B0.095693F0**
  **Content-Type: text/plain;**
  **.name="NEWS.txt"**
  **Content-Transfer-Encoding: quoted-printable**
  **Content-Disposition: attachment;**
  **.filename="NEWS.txt"**

  **Version 4.9.9.1**
  *** Many bug fixes**
  *** Improved editor**
  **...edited...**
  SMTP client: **From: "Gurpartap Singh" <gurpartap@patriots.in>**
  **To: <raj_deol2002in@yahoo.co.in>**
  **Subject: SMTP**
  **Date: Mon, 5 Oct 2009 11:36:07 +0530**
  **Message-ID: <000301ca4581$ef9e57f0$cedb07d0$@in>**
  **MIME-Version: 1.0**
  **Content-Type: multipart/mixed;**
  **.boundary="----=_NextPart_000_0004_01CA45B0.095693F0"**
  **X-Mailer: Microsoft Office Outlook 12.0**
  **Thread-Index: AcpFgem9BvjjZEDeR1Kh8i+hUyVo0A==**
  **Content-Language: en-us**
  **x-cr-hashedpuzzle: SeA= AAR2 ADaH BpiO C4G1 D1gW FNB1 FPkR Fn+W HFCP HnYJ JO7s Kum6 KytW LFcI LjUt;1;cgBhAGoAXwBkAGUAbwBsADIAMAAwADIAaQBuAEAAeQBhAGgAbwBvAC4AYwBvAC4AaQBuAA==;Sosha1_v1;7;{CAA37F59-1850-45C7-8540-AA27696B5398};ZwB1AHIAcABhAHIAdABhAHAAQABwAGEAdAByAGkAbwB0AHMALgBpAG4A;Mon, 05 Oct 2009 06:06:01 GMT;UwBNAFQAUAA=**
  **x-cr-puzzleid: {CAA37F59-1850-45C7-8540-AA27696B5398}**

  **This is a multipart message in MIME format.**

  **------=_NextPart_000_0004_01CA45B0.095693F0**
  **Content-Type: multipart/alternative;**
  **.boundary="----=_NextPart_001_0005_01CA45B0.095693F0"**


  **------=_NextPart_001_0005_01CA45B0.095693F0**
  **Content-Type: text/plain;**
  **.charset="us-ascii"**
  **Content-Transfer-Encoding: 7bit**

  **Hello**



  **I send u smtp pcap file**

  **Find the attachment**



  **GPS**


  **------=_NextPart_001_0005_01CA45B0.095693F0**
  **Content-Type: text/html;**
  **.charset="us-ascii"**
  **Content-Transfer-Encoding: quoted-printable**

  **<html xmlns:v=3D"urn:schemas-microsoft-com:vml" =**
  **xmlns:o=3D"urn:schemas-microsoft-com:office:office" =**
  **xmlns:w=3D"urn:schemas**
  **SMTP client: -microsoft-com:office:word" =**
  **xmlns:m=3D"http://schemas.microsoft.com/office/2004/12/omml" =**
  **xmlns=3D"http://www.w3.org/TR/REC-html40">**

  **<head>**
  **<META HTTP-EQUIV=3D"Content-Type" CONTENT=3D"text/html; =**
  **charset=3Dus-ascii">**
  **<meta name=3DGenerator content=3D"Microsoft Word 12 (filtered medium)">**
  **<style>**
  **...edited...**
  **  <o:idmap v:ext=3D"edit" data=3D"1" />**
  ** </o:shapelayout></xml><![endif]-->**
  **</head>**

  **<body lang=3DEN-US link=3Dblue vlink=3Dpurple>**

  **<div cl**
  SMTP client: **ass=3DSection1>**

  **<p class=3DMsoNormal>Hello<o:p></o:p></p>**

  **<p class=3DMsoNormal><o:p>&nbsp;</o:p></p>**

  **<p class=3DMsoNormal>I send u smtp pcap file <o:p></o:p></p>**

  **<p class=3DMsoNormal>Find the attachment<o:p></o:p></p>**

  **<p class=3DMsoNormal><o:p>&nbsp;</o:p></p>**

  **<p class=3DMsoNormal>GPS<o:p></o:p></p>**

  **</div>**

  **</body>**

  **</html>**

  **------=_NextPart_001_0005_01CA45B0.095693F0--**

  **------=_NextPart_000_0004_01CA45B0.095693F0**
  **Content-Type: text/plain;**
  **.name="NEWS.txt"**
  **Content-Transfer-Encoding: quoted-printable**
  **Content-Disposition: attachment;**
  **.filename="NEWS.txt"**

  **Version 4.9.9.1**
  *** Many bug fixes**
  *** Improved editor**
  **...edited...**
  *** Allow user to specify an alternate configuration file in Environment =**
  **Options=20**
  **...edited...**
  **Version 4.9.4.1 (5.0 beta 4.1):**

  *** back to gcc 2.95.3**
  *** Profiling support**
  *** new update/packages checker (vUpdate)**
  *** Lots of bugfixes**

  **------=_NextPart_000_00**
  SMTP client: **04_01CA45B0.095693F0--**

  .

  SMTP server: 250 OK id=1Mugho-0003Dg-Un

  SMTP client: **QUIT**

  SMTP server: 221 xc90.websitewelcome.com closing connection

Looking at these transcripts, it looks like a single message in text and HTML
formats, sent with ``Message-ID: <000301ca4581$ef9e57f0$cedb07d0$@in>``, was
transmitted. It included an attachment that looks like the release notes for
software. Let’s see what Zeek can make of this.

Inspecting the :file:`smtp.log`
===============================

One of the best aspects of Zeek is making sense of all of the information
present in a protocol that Zeek understands. Here is the entry from the
:file:`smtp.log` for the email shown above.

::

  {
    "ts": 1254722768.219663,
    "uid": "C1qe8w3QHRF2N5tVV5",
    "id.orig_h": "10.10.1.4",
    "id.orig_p": 1470,
    "id.resp_h": "74.53.140.153",
    "id.resp_p": 25,
    "trans_depth": 1,
    "helo": "GP",
    "mailfrom": "gurpartap@patriots.in",
    "rcptto": [
      "raj_deol2002in@yahoo.co.in"
    ],
    "date": "Mon, 5 Oct 2009 11:36:07 +0530",
    "from": "\"Gurpartap Singh\" <gurpartap@patriots.in>",
    "to": [
      "<raj_deol2002in@yahoo.co.in>"
    ],
    "msg_id": "<000301ca4581$ef9e57f0$cedb07d0$@in>",
    "subject": "SMTP",
    "last_reply": "250 OK id=1Mugho-0003Dg-Un",
    "path": [
      "74.53.140.153",
      "10.10.1.4"
    ],
    "user_agent": "Microsoft Office Outlook 12.0",
    "tls": false,
    "fuids": [
      "Fel9gs4OtNEV6gUJZ5",
      "Ft4M3f2yMvLlmwtbq9",
      "FL9Y0d45OI4LpS6fmh"
    ]
  }

Fields like the ``mailfrom``, ``rcptto``, ``from``, and ``to`` fields are also
easy to see in this log output. The ``user_agent``, IP addresses involved in
transmission (``path``), and the ``msg_id`` are also easy to find. Finally,
Zeek provides three file identifiers that we can use to find associated
extracted files, if any are present.

Inspecting Extracted Files
==========================

A look into the :file:`extracted_files/` directory yields the following
entries:

.. code-block:: console

  $ file extract_files/*

::

  extract_files/SMTP-Fel9gs4OtNEV6gUJZ5.txt: ASCII text, with CRLF line terminators
  extract_files/SMTP-FL9Y0d45OI4LpS6fmh.txt: ASCII text, with CRLF line terminators

We see two files here, both in ASCII text format. They have two of the three
file identifiers seen in the :file:`smtp.log` entry. The third is likely not
present because this instance of Zeek was configured to only extract files in
text format.

Let’s look at the two files using the head application, which by default only
provides the first 10 lines.

.. code-block:: console

  $ head extract_files/SMTP-Fel9gs4OtNEV6gUJZ5.txt

::

  Hello



  I send u smtp pcap file

  Find the attachment

.. code-block:: console

  $ head extract_files/SMTP-FL9Y0d45OI4LpS6fmh.txt

::

  Version 4.9.9.1
  * Many bug fixes
  * Improved editor

  Version 4.9.9.0
  * Support for latest Mingw compiler system builds
  * Bug fixes

  Version 4.9.8.9
  * New code tooltip display

The first file is the content of the email message. The second file is the
beginning of the attachment.

Inspecting Zeek Logs for Traffic to Port 465 TCP
================================================

Analysts are more likely to find encrypted SMTP traffic in modern environments.
Encrypted SMTP traffic will likely use either port 465 TCP or 587 TCP. In this
example, we will look at Zeek logs for SMTP traffic using port 465 TCP.

You may see port 465 TCP as “SMTPS,” meaning “SMTP Secure.” This is a defacto
standard, although it was not officially ratified by the Internet Assigned
Numbers Authority (IANA). In fact, IANA has assigned port 465 TCP to the “URL
Rendezvous Directory for SSM,” where SSM probably means Source-Specific
Multicast (SSM). However, IANA’s Service Name and Transport Protocol Port
Number Registry also lists “Message Submission over TLS” for port 465 TCP,
which is the encrypted version of its entry for port 25 TCP and SMTP.

http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt

In any case, for a sample SMTPS of port 465 TCP traffic for SMTP connection,
Zeek produced the following logs.

First is a :file:`conn.log` entry, where SSL is seen as the service:

.. literal-emph::

  {
    "ts": "2020-08-15T13:14:33.101858Z",
    "uid": "CZ4iBM3vh98hH5GmV",
    "id.orig_h": "192.168.4.43",
    "id.orig_p": 61329,
    "id.resp_h": "74.125.192.108",
    **"id.resp_p": 465,**
    "proto": "tcp",
    **"service": "ssl",**
    "duration": 0.08411312103271484,
    "orig_bytes": 348,
    "resp_bytes": 3257,
    "conn_state": "SF",
    "local_orig": true,
    "local_resp": false,
    "missed_bytes": 0,
    "history": "ShADdafF",
    "orig_pkts": 11,
    "orig_ip_bytes": 800,
    "resp_pkts": 10,
    "resp_ip_bytes": 3669,
    "community_id": "1:NArgsDn5hgq6xjy6xTiMPZCgDKE="
  }

Zeek created two :file:`files.log` entries for observed x509 certificates:

.. literal-emph::

  {
    "ts": "2020-08-15T13:14:33.157292Z",
    "fuid": "F2cHKgS8RS2OyLdI4",
    "uid": "CZ4iBM3vh98hH5GmV",
    "id.orig_h": "192.168.4.43",
    "id.orig_p": 61329,
    "id.resp_h": "74.125.192.108",
    "id.resp_p": 465,
    "source": "SSL",
    "depth": 0,
    "analyzers": [
      "X509",
      "MD5",
      "SHA1"
    ],
    **"mime_type": "application/x-x509-user-cert",**
    "duration": 0,
    "local_orig": false,
    "is_orig": false,
    "seen_bytes": 1228,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false,
    "md5": "772f22ceaa7d6e285a9068718e8251af",
    "sha1": "5849d577c3f434125724459e3b32025247fda56d"
  }

  {
    "ts": "2020-08-15T13:14:33.157292Z",
    "fuid": "Fl9EEK26t5qzDVW3vf",
    "uid": "CZ4iBM3vh98hH5GmV",
    "id.orig_h": "192.168.4.43",
    "id.orig_p": 61329,
    "id.resp_h": "74.125.192.108",
    "id.resp_p": 465,
    "source": "SSL",
    "depth": 0,
    "analyzers": [
      "X509",
      "MD5",
      "SHA1"
    ],
    **"mime_type": "application/x-x509-ca-cert",**
    "duration": 0,
    "local_orig": false,
    "is_orig": false,
    "seen_bytes": 1102,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false,
    "md5": "dbb23c939236012e71d5f44dbc2acea0",
    "sha1": "dfe2070c79e7ff36a925ffa327ffe3deecf8f9c2"
  }

Finally Zeek created a :file:`ssl.log` entry with a ``server_name`` field that
helps us see that the encrypted traffic was probably SMTP:

.. literal-emph::

  {
    "ts": "2020-08-15T13:14:33.157292Z",
    "uid": "CZ4iBM3vh98hH5GmV",
    "id.orig_h": "192.168.4.43",
    "id.orig_p": 61329,
    "id.resp_h": "74.125.192.108",
    "id.resp_p": 465,
    "version": "TLSv12",
    "cipher": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "curve": "x25519",
    **"server_name": "smtp.gmail.com",**
    "resumed": false,
    "established": true,
    "cert_chain_fuids": [
      "F2cHKgS8RS2OyLdI4",
      "Fl9EEK26t5qzDVW3vf"
    ],
    "client_cert_chain_fuids": [],
    "validation_status": "ok"
  }

Inspecting Zeek Logs for Traffic to Port 587 TCP
================================================

The default server port for encrypted SMTP message submission is port 587 TCP.

For a sample SMTPS of port 587 TCP traffic for SMTP connection, Zeek produced
the following logs.

First is a :file:`conn.log` entry, where SSL and SMTP are seen as the services:

.. literal-emph::

  {
    "ts": "2020-08-09T23:31:46.626484Z",
    "uid": "CCqmLfIrqQeWvXol4",
    "id.orig_h": "192.168.4.41",
    "id.orig_p": 49334,
    **"id.resp_h": "17.42.251.41",**
    "id.resp_p": 587,
    "proto": "tcp",
    "**service": "ssl,smtp",**
    "duration": 61.12906002998352,
    "orig_bytes": 1659,
    "resp_bytes": 7198,
    "conn_state": "SF",
    "local_orig": true,
    "local_resp": false,
    "missed_bytes": 0,
    "history": "ShAdDafFr",
    "orig_pkts": 29,
    "orig_ip_bytes": 3179,
    "resp_pkts": 26,
    "resp_ip_bytes": 8534,
    "community_id": "1:wM+UdwdNy9VK/LEhFBTcQCtAqo8="
  }

Note that is different from the port 465 TCP session, where only SSL was noted.

Next are three :file:`files.log` entries for x509 certificates.

.. literal-emph::

  {
    "ts": "2020-08-09T23:31:46.800843Z",
    "fuid": "FmLTdUtlSHFynFf4j",
    "uid": "CCqmLfIrqQeWvXol4",
    "id.orig_h": "192.168.4.41",
    "id.orig_p": 49334,
    "id.resp_h": "17.42.251.41",
    "id.resp_p": 587,
    "source": "SSL",
    "depth": 0,
    "analyzers": [
      "X509",
      "SHA1",
      "MD5"
    ],
    **"mime_type": "application/x-x509-user-cert",**
    "duration": 0,
    "local_orig": false,
    "is_orig": false,
    "seen_bytes": 3939,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false,
    "md5": "484d47f1b847d67981eade5b2b1f5618",
    "sha1": "c262f01e83d6ce0c361e8b049e5be8fe6e55806b"
  }
  {
    "ts": "2020-08-09T23:31:46.800843Z",
    "fuid": "F5ITBU2e5kcvYpOZJd",
    "uid": "CCqmLfIrqQeWvXol4",
    "id.orig_h": "192.168.4.41",
    "id.orig_p": 49334,
    "id.resp_h": "17.42.251.41",
    "id.resp_p": 587,
    "source": "SSL",
    "depth": 0,
    "analyzers": [
      "X509",
      "SHA1",
      "MD5"
    ],
    **"mime_type": "application/x-x509-ca-cert",**
    "duration": 0,
    "local_orig": false,
    "is_orig": false,
    "seen_bytes": 1092,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false,
    "md5": "48f0e38385112eeca5fc9ffd402eaecd",
    "sha1": "8e8321ca08b08e3726fe1d82996884eeb5f0d655"
  }
  {
    "ts": "2020-08-09T23:31:46.800843Z",
    "fuid": "F453Xk1oZcMiI6X3a7",
    "uid": "CCqmLfIrqQeWvXol4",
    "id.orig_h": "192.168.4.41",
    "id.orig_p": 49334,
    "id.resp_h": "17.42.251.41",
    "id.resp_p": 587,
    "source": "SSL",
    "depth": 0,
    "analyzers": [
      "X509",
      "SHA1",
      "MD5"
    ],
    **"mime_type": "application/x-x509-ca-cert",**
    "duration": 0,
    "local_orig": false,
    "is_orig": false,
    "seen_bytes": 856,
    "missing_bytes": 0,
    "overflow_bytes": 0,
    "timedout": false,
    "md5": "f775ab29fb514eb7775eff053c998ef5",
    "sha1": "de28f4a4ffe5b92fa3c503d1a349a7f9962a8212"
  }

Next we have a :file:`smtp.log` entry that shows the clear text fields Zeek
could extract prior to the negotiation of encryption:

.. literal-emph::

  {
    "ts": "2020-08-09T23:31:46.696892Z",
    "uid": "CCqmLfIrqQeWvXol4",
    "id.orig_h": "192.168.4.41",
    "id.orig_p": 49334,
    "id.resp_h": "17.42.251.41",
    **"id.resp_p": 587,**
    "trans_depth": 1,
    **"helo": "[192.168.4.41]",**
    **"last_reply": "220 2.0.0 Ready to start TLS",**
    "path": [
      "17.42.251.41",
      "192.168.4.41"
    ],
    "tls": true,
    "fuids": [],
    "is_webmail": false
  }

Finally we have a :file:`ssl.log` entry with a helpful ``server_name`` implying
that this SMTP traffic.

.. literal-emph::

  {
    "ts": "2020-08-09T23:31:46.800843Z",
    "uid": "CCqmLfIrqQeWvXol4",
    "id.orig_h": "192.168.4.41",
    "id.orig_p": 49334,
    "id.resp_h": "17.42.251.41",
    **"id.resp_p": 587,**
    "version": "TLSv12",
    "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "curve": "secp256r1",
    **"server_name": "p71-smtp.mail.me.com",**
    "resumed": false,
    "established": true,
    "cert_chain_fuids": [
      "FmLTdUtlSHFynFf4j",
      "F5ITBU2e5kcvYpOZJd",
      "F453Xk1oZcMiI6X3a7"
    ],
    "client_cert_chain_fuids": [],
    "validation_status": "ok"
  }

It is helpful that the more standardized protocol running on port 587 TCP has
more SMTP-related coverage, despite being encrypted.

Other Email Protocols: IMAP over TLS
====================================

Before finishing this section, it might be helpful to look at two other email
protocols and what Zeek makes of them.

Internet Message Access Protocol (IMAP) is a protocol that clients use to
retrieve email from mail servers. The server for the clear-text variant listens
on port 143 TCP. The encrypted variant, IMAP over TLS (referred to earlier as
IMAP over SSL), listens on port 993 TCP.

There is currently no :file:`imap.log` created by Zeek for the unencrypted or
encrypted variants.

The following example shows what Zeek sees when IMAP over TLS is active on port
993 TCP.

Zeek creates a :file:`conn.log` entry, as per usual, with the next service
identified as SSL:

.. literal-emph::

  {
    "ts": "2020-08-17T03:01:16.752745Z",
    "uid": "CZzvVe1KOD9D1TewCk",
    "id.orig_h": "192.168.4.23",
    "id.orig_p": 61579,
    "id.resp_h": "172.253.122.108",
    **"id.resp_p": 993,**
    "proto": "tcp",
    **"service": "ssl",**
    "duration": 0.8354301452636719,
    "orig_bytes": 1582,
    "resp_bytes": 2499,
    "conn_state": "SF",
    "local_orig": true,
    "local_resp": false,
    "missed_bytes": 0,
    "history": "ShADadFfR",
    "orig_pkts": 37,
    "orig_ip_bytes": 3482,
    "resp_pkts": 35,
    "resp_ip_bytes": 4327,
    "community_id": "1:Ug0SOBN+9zdqsSiesc5zQf9mr+I="
  }

The ``server_name`` in the :file:`ssl.log` entry indicates that this is a IMAP
session.

.. literal-emph::

  {
    "ts": "2020-08-17T03:01:16.865252Z",
    "uid": "CZzvVe1KOD9D1TewCk",
    "id.orig_h": "192.168.4.23",
    "id.orig_p": 61579,
    "id.resp_h": "172.253.122.108",
    **"id.resp_p": 993,**
    **"version": "TLSv13",**
    "cipher": "TLS_AES_128_GCM_SHA256",
    "curve": "x25519",
    **"server_name": "imap.gmail.com",**
    "resumed": true,
    "established": true
  }

Note the use of TLS 1.3. Because this protocol is used, we do not have
certificate details, i.e., there are no :file:`files.log` or :file:`x509.log`
details.

Other Email Protocols: POP over TLS
===================================

A protocol similar to IMAP using a different port is Post Office Protocol
(POP). The traditional unencrypted server listens on port 110 TCP. The
encrypted variant listens on port 995 TCP. As before, here are two entries.

There is currently no :file:`pop.log` created by Zeek for the unencrypted or
encrypted variants.

The following example shows what Zeek sees when POP over TLS is active on port
995 TCP.

Zeek creates a :file:`conn.log` entry, as per usual, with the next service
identified as SSL:

.. literal-emph::

  {
    "ts": "2020-07-02T21:19:34.048427Z",
    "uid": "CzhwYd95h2GWh9bD8",
    "id.orig_h": "192.168.4.42",
    "id.orig_p": 50938,
    "id.resp_h": "142.250.31.109",
    **"id.resp_p": 995,**
    "proto": "tcp",
    **"service": "ssl",**
    "duration": 11.121870994567871,
    "orig_bytes": 2056,
    "resp_bytes": 1034478,
    "conn_state": "SF",
    "local_orig": true,
    "local_resp": false,
    "missed_bytes": 0,
    "history": "ShADadtfFr",
    "orig_pkts": 226,
    "orig_ip_bytes": 11156,
    "resp_pkts": 865,
    "resp_ip_bytes": 1075618,
    "community_id": "1:41G4TR4OvkRdEhCPft5bqJWyJVc="
  }

The ``server_name`` in the :file:`ssl.log` entry indicates that this is a IMAP
session.

.. literal-emph::

  {
    "ts": "2020-07-02T21:19:34.067004Z",
    "uid": "CzhwYd95h2GWh9bD8",
    "id.orig_h": "192.168.4.42",
    "id.orig_p": 50938,
    "id.resp_h": "142.250.31.109",
    **"id.resp_p": 995,**
    **"version": "TLSv13",**
    "cipher": "TLS_AES_128_GCM_SHA256",
    "curve": "x25519",
    **"server_name": "pop.gmail.com",**
    "resumed": true,
    "established": true
  }

Again note the use of TLS 1.3. Because this protocol is used, we do not have
certificate details, i.e., there are no :file:`files.log` or :file:`x509.log`
details.

Conclusion
==========

This section showed how Zeek renders logs for SMTP traffic, whether using an
older clear text or modern encrypted version. It is helpful to query Zeek logs
periodically to determine what sorts of SMTP traffic is present in your
environment.
