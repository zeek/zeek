=======
rdp.log
=======

Remote Desktop Protocol (RDP) is a protocol Microsoft developed to enable
remote graphical communication. RDP implementations exist for other operating
systems, but RDP is most popular on systems running Windows NT 4.0 and newer.

Older versions of RDP are unencrypted, while newer versions offer SSL and TLS
encryption.

Standard RDP servers listen on port 3389 TCP. Administrators can configure the
service to listen on any port, however. The following material investigates the
process by which a simulated intruder gains access to a system via RDP. First
he makes many connections to the RDP server, testing usernames and passwords.
Following the correct guessing of a username and password, he connects and
briefly interacts with the system offering access via RDP.

For full details on each field in the :file:`rdp.log` file, please refer to
:zeek:see:`RDP::Info`.

:file:`conn.log`
================

Let’s start with the :file:`conn.log` for the activity in question. I’ve broken
it into two sets of activities. The first is the reconnaissance and the second
is the interactive session.

I’ve summarized the first set of :file:`conn.log` entries using the following syntax:

.. code-block:: console

  $ jq -c '[."id.orig_h", ."id.resp_h", ."id.resp_p", ."service", ."orig_bytes", ."resp_bytes"]' conn.log | sort | uniq -c

::

     38 ["192.168.4.160","192.168.4.161",3389,"ssl",1392,1238]
      1 ["192.168.4.160","192.168.4.161",3389,"ssl",3365,4855]

We see 38 sessions which contain the same number of bytes sent and received by
the client and server, and 1 session which contains a different number of
bytes. That could indicate a successful connection. Port 3389 TCP is the
destination, but remember that any TCP port could host a RDP server. Also note
Zeek reports the service as SSL, because this RDP session is encrypted by TLS.

The second set of :file:`conn.log` entries contains the following session:

.. literal-emph::

  {
    "ts": 1607353272.790635,
    "uid": "CFdEZNjN5MtPzGMS8",
    **"id.orig_h": "192.168.4.160",**
    "id.orig_p": 59758,
    **"id.resp_h": "192.168.4.161",**
    **"id.resp_p": 3389,**
    "proto": "tcp",
    **"service": "ssl",**
    "duration": 109.49137687683105,
    **"orig_bytes": 66747,**
    **"resp_bytes": 1823511,**
    "conn_state": "RSTR",
    "missed_bytes": 0,
    "history": "ShADdaFr",
    "orig_pkts": 2913,
    "orig_ip_bytes": 183287,
    "resp_pkts": 2250,
    "resp_ip_bytes": 1913523
  }

This activity is similar to the previous, except that the client and server
have sent many more bytes of data.

:file:`rdp.log`
===============

The following syntax summarizes the relevant content in the first set of Zeek
:file:`rdp.log` entries, caused by the simulated intruder’s RDP reconnaissance:

.. code-block:: console

  $ jq -c '[."id.orig_h", ."id.resp_h", ."id.resp_p", ."cookie", ."result", ."security_protocol", ."cert_count"]' rdp.log | sort | uniq -c

::

     39 ["192.168.4.160","192.168.4.161",3389,"test","encrypted","HYBRID",0]

There is nothing in these logs to indicate whether the session was successful
or not. However, Zeek was able to determine that RDP was in use, based on its
recognition of the protocol.

Here is the entire :file:`rdp.log` entry for the interactive RDP session:

.. literal-emph::

  {
    "ts": 1607353272.791158,
    "uid": "CFdEZNjN5MtPzGMS8",
    **"id.orig_h": "192.168.4.160",**
    "id.orig_p": 59758,
    **"id.resp_h": "192.168.4.161",**
    **"id.resp_p": 3389,**
    "cookie": "test",
    "result": "encrypted",
    "security_protocol": "HYBRID",
    "cert_count": 0
  }

As before, there is nothing stating that this is an interactive session.

:file:`ssl.log` and :file:`x509.log`
====================================

The Zeek logs associated with TLS-encrypted sessions might tell us a bit about
the RDP server. Here is a :file:`ssl.log` entry for the interactive session:

.. literal-emph::

  {
    "ts": 1607353272.79572,
    "uid": "CFdEZNjN5MtPzGMS8",
    **"id.orig_h": "192.168.4.160",**
    "id.orig_p": 59758,
    **"id.resp_h": "192.168.4.161",**
    **"id.resp_p": 3389,**
    **"version": "TLSv12",**
    **"cipher": "TLS_RSA_WITH_AES_256_GCM_SHA384",**
    **"server_name": "192.168.4.161",**
    "resumed": false,
    "established": true,
    "cert_chain_fuids": [
      **"FWesoX2H43hXhuqoGb"**
    ],
    "client_cert_chain_fuids": [],
    **"subject": "CN=WinDev2010Eval",**
    **"issuer": "CN=WinDev2010Eval"**
  }

From this information it looks like the target is a Windows development server.

Here is the corresponding :file:`x509.log` entry. We match it to the preceding
:file:`ssl.log` entry using the ``id`` field.

.. literal-emph::

  {
    "ts": 1607353272.79572,
    **"id": "FWesoX2H43hXhuqoGb",**
    "certificate.version": 3,
    "certificate.serial": "5578FF9983F26AA6442533AB6AD54C72",
    **"certificate.subject": "CN=WinDev2010Eval",**
    **"certificate.issuer": "CN=WinDev2010Eval",**
    "certificate.not_valid_before": 1602434171,
    "certificate.not_valid_after": 1618245371,
    "certificate.key_alg": "rsaEncryption",
    "certificate.sig_alg": "sha256WithRSAEncryption",
    "certificate.key_type": "rsa",
    "certificate.key_length": 2048,
    "certificate.exponent": "65537"
  }

While this might have some significance in other investigations, here it is not
as important.

Running the Test
================

For those who might want to simulate this activity themselves, I wanted to
share how I conducted this experiment.

.. code-block:: console

  $ hydra -t 1 -V -f -l test -P wordlist.txt rdp://192.168.4.161

.. literal-emph::

  Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

  Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-12-07 09:46:30
  [WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
  [DATA] max 1 task per 1 server, overall 1 task, 4999 login tries (l:1/p:4999), ~4999 tries per task
  [DATA] attacking rdp://192.168.4.161:3389/
  [ATTEMPT] target 192.168.4.161 - login "test" - pass "123456" - 1 of 4999 [child 0] (0/0)
  [ATTEMPT] target 192.168.4.161 - login "test" - pass "12345" - 2 of 4999 [child 0] (0/0)
  [ATTEMPT] target 192.168.4.161 - login "test" - pass "123456789" - 3 of 4999 [child 0] (0/0)
  [ATTEMPT] target 192.168.4.161 - login "test" - pass "password" - 4 of 4999 [child 0] (0/0)
  ...edited...
  [ATTEMPT] target 192.168.4.161 - login "test" - pass "liverpool" - 38 of 4999 [child 0] (0/0)
  **[ATTEMPT] target 192.168.4.161 - login "test" - pass "football" - 39 of 4999 [child 0] (0/0)**
  **[3389][rdp] host: 192.168.4.161   login: test   password: football**
  [STATUS] attack finished for 192.168.4.161 (valid pair found)
  **1 of 1 target successfully completed, 1 valid password found**
  Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-12-07 09:46:53

I used the reconnaissance tool THC-Hydra by van Hauser/THC & David Maciejak. I
provided a word list that had a password that I had enabled on a test account
on the Windows RDP server at ``192.168.4.161``. I ran Hydra from a Kali Linux
virtual machine against a Windows 10 development virtual machine and captured
the traffic on Kali Linux. I then processed it with Zeek to produce the logs in
this section.

Conclusion
==========

When processing unencrypted RDP sessions, Zeek can provide a bit more
information than that provided here. However, in my experience Zeek is most
helpful for identifying systems which should or should not be offering RDP
services. Zeek will also generate records for interactive sessions, helping
analysts identify when authorized or unauthorized users access systems via RDP.

For more information on analyzing RDP in context of vulnerabilities that
appeared in 2020, please see the following blog posts:

https://corelight.blog/2019/05/23/how-to-use-corelight-and-zeek-logs-to-mitigate-rds-rdp-vulnerabilities/

https://corelight.blog/2020/05/13/analyzing-encrypted-rdp-connections/
