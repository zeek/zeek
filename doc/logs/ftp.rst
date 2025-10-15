=======
ftp.log
=======

Zeek’s :file:`ftp.log` summarizes activity using the File Transfer Protocol
(FTP).  Similar to the http.log, :file:`ftp.log` captures the essential
information an analyst would likely need to understand how a client and server
interact using FTP.

FTP is an interesting protocol in the sense that it uses one TCP connection as
a control channel and a second TCP connection as a file transfer channel. The
control channel usually involves a FTP server listening on port 21 TCP. The
file transfer channel, however, depends on the choices made by the client and
server. With “passive FTP,” the server advertises a second TCP port to which
the client should connect, and the client connects to that TCP port to initiate
the file transfer. With “active FTP,” the server connects to a TCP port
advertised by the client, although the server uses a source port of 20 TCP. It
is more common to see passive FTP on the Internet today due to middleboxes
(such as firewalls or other filtering devices) interfering with active FTP
connections inbound to clients.

For full details on each field in the :file:`ftp.log` file, please refer to
:zeek:see:`FTP::Info`.

Finding the :file:`ftp.log`
===========================

In the following example, an analyst knows to look for Zeek logs on a specific
day bearing a specific UID. They search in the specified directory using the
:program:`zgrep` command and pipe the results to the Unix command
:program:`sed`, removing characters prior to the ``.gz:`` that would appear in
the output. This facilitates piping the results into the :program:`jq` utility
for easier viewing.

.. code-block:: console

  $ zgrep "CLkXf2CMo11hD8FQ5" 2020-08-16/* | sed 's/.*gz://' | jq .

::

  {
    "_path": "conn",
    "_system_name": "ds61",
    "_write_ts": "2020-08-16T06:26:10.266225Z",
    "_node": "worker-01",
    "ts": "2020-08-16T06:26:01.485394Z",
    "uid": "CLkXf2CMo11hD8FQ5",
    "id.orig_h": "192.168.4.76",
    "id.orig_p": 53380,
    "id.resp_h": "196.216.2.24",
    "id.resp_p": 21,
    "proto": "tcp",
    "service": "ftp",
    "duration": 3.780829906463623,
    "orig_bytes": 184,
    "resp_bytes": 451,
    "conn_state": "SF",
    "local_orig": true,
    "local_resp": false,
    "missed_bytes": 0,
    "history": "ShAdDafF",
    "orig_pkts": 20,
    "orig_ip_bytes": 1232,
    "resp_pkts": 17,
    "resp_ip_bytes": 1343,
    "community_id": "1:lEESxqaSVYqFZvWNb4OccTa9sTs="
  }
  {
    "_path": "ftp",
    "_system_name": "ds61",
    "_write_ts": "2020-08-16T06:26:04.077276Z",
    "_node": "worker-01",
    "ts": "2020-08-16T06:26:03.553287Z",
    "uid": "CLkXf2CMo11hD8FQ5",
    "id.orig_h": "192.168.4.76",
    "id.orig_p": 53380,
    "id.resp_h": "196.216.2.24",
    "id.resp_p": 21,
    "user": "anonymous",
    "password": "ftp@example.com",
    "command": "EPSV",
    "reply_code": 229,
    "reply_msg": "Entering Extended Passive Mode (|||31746|).",
    "data_channel.passive": true,
    "data_channel.orig_h": "192.168.4.76",
    "data_channel.resp_h": "196.216.2.24",
    "data_channel.resp_p": 31746
  }
  {
    "_path": "ftp",
    "_system_name": "ds61",
    "_write_ts": "2020-08-16T06:26:05.117287Z",
    "_node": "worker-01",
    "ts": "2020-08-16T06:26:04.597290Z",
    "uid": "CLkXf2CMo11hD8FQ5",
    "id.orig_h": "192.168.4.76",
    "id.orig_p": 53380,
    "id.resp_h": "196.216.2.24",
    "id.resp_p": 21,
    "user": "anonymous",
    "password": "ftp@example.com",
    "command": "RETR",
    "arg": "ftp://196.216.2.24/pub/stats/afrinic/delegated-afrinic-extended-latest.md5",
    "file_size": 74,
    "reply_code": 226,
    "reply_msg": "Transfer complete.",
    "fuid": "FueF95uKPrUuDnMc4"
  }

This output presents three log files. The first is a :file:`conn.log` entry for
the FTP control channel connection involving port 21 TCP. The second two
describe what happened during the FTP control channel.

Before looking at the details, let’s see a reconstruction of the FTP control
channel.

Reconstructing the FTP Control Channel
======================================

In the following example, we use the :program:`tcpflow` program introduced in
the :file:`http.log` section to reconstruct the FTP control channel. By using
the ``-c`` option, we can tell :program:`tcpflow`` to interleave the traffic
sent by both sides of the conversation.  I pass it the port 53380 parameter to
be sure I reconstruct traffic involving that connection, which was the source
port for the FTP client. (If I chose something like 21 TCP instead, I could
have reconstructed numerous FTP sessions beyond the one in question here.)

In this example, ``196.216.2.24`` is the FTP server, and ``192.168.4.76`` is
the FTP client.

After the first two entries, I have manually edited the output for readability.

.. code-block:: console

  $ tcpflow -c -r snort.log.1597554100-196.216.2.24.pcap port 53380

.. literal-emph::

  196.216.002.024.00021-192.168.004.076.53380 [**server** to client]: 220 ::::: Welcome to the AFRINIC FTP service ::::::

  192.168.004.076.53380-196.216.002.024.00021 [**client** to server]: USER anonymous

  server: 331 Please specify the password.

  client: PASS ftp@example.com

  server: 230 Login successful.

  client: PWD

  server: 257 "/"

  client: CWD pub

  server: 250 Directory successfully changed.

  client: CWD stats

  server: 250 Directory successfully changed.

  client: CWD afrinic

  server: 250 Directory successfully changed.

  client: EPSV

  server: 229 Entering Extended Passive Mode (|||31746|).

  client: TYPE I

  server: 200 Switching to Binary mode.

  client: SIZE delegated-afrinic-extended-latest.md5

  server: 213 74

  client: RETR delegated-afrinic-extended-latest.md5

  server: 150 Opening BINARY mode data connection for delegated-afrinic-extended-latest.md5 (74 bytes).

  server: 226 Transfer complete.

  client: QUIT

  server: 221 Goodbye.

Reading this transcript, some important items include the following:

* This is a FTP server that allows anonymous access.
* The data channel occurs using passive FTP.
* The FTP server opens port 31746 TCP to accept the FTP connection over which
  it will transfer the requested file.
* The file transferred is ``delegated-afrinic-extended-latest.md5``, a 74 byte
  file.

With this understanding in place, let’s see how Zeek represents this activity.

Inspecting the ftp.log
======================

Let’s take a second look at the two :file:`ftp.log` entries.

::

  {
    "_path": "ftp",
    "_system_name": "ds61",
    "_write_ts": "2020-08-16T06:26:04.077276Z",
    "_node": "worker-01",
    "ts": "2020-08-16T06:26:03.553287Z",
    "uid": "CLkXf2CMo11hD8FQ5",
    "id.orig_h": "192.168.4.76",
    "id.orig_p": 53380,
    "id.resp_h": "196.216.2.24",
    "id.resp_p": 21,
    "user": "anonymous",
    "password": "ftp@example.com",
    "command": "EPSV",
    "reply_code": 229,
    "reply_msg": "Entering Extended Passive Mode (|||31746|).",
    "data_channel.passive": true,
    "data_channel.orig_h": "192.168.4.76",
    "data_channel.resp_h": "196.216.2.24",
    "data_channel.resp_p": 31746
  }

The first :file:`ftp.log` entry shows us that the FTP client logged in as user
``ftp@example.com``, requested a form of passive connection for its data
channel, and the server offered port 31746 TCP for that connection.

::

  {
    "_path": "ftp",
    "_system_name": "ds61",
    "_write_ts": "2020-08-16T06:26:05.117287Z",
    "_node": "worker-01",
    "ts": "2020-08-16T06:26:04.597290Z",
    "uid": "CLkXf2CMo11hD8FQ5",
    "id.orig_h": "192.168.4.76",
    "id.orig_p": 53380,
    "id.resp_h": "196.216.2.24",
    "id.resp_p": 21,
    "user": "anonymous",
    "password": "ftp@example.com",
    "command": "RETR",
    "arg": "ftp://196.216.2.24/pub/stats/afrinic/delegated-afrinic-extended-latest.md5",
    "file_size": 74,
    "reply_code": 226,
    "reply_msg": "Transfer complete.",
    "fuid": "FueF95uKPrUuDnMc4"
  }

The second :file:`ftp.log` entry gives details on the file retrieved from the
FTP server, such as the path on the server, its name, and the fact that the
file transfer completed. We also have a file identifier (``FueF95uKPrUuDnMc4``)
that we could use to find the file on disk, if we configured Zeek to extract
and save this sort of content.

Finding the Data Channel
========================

For the sake of completeness, let’s take a look at the FTP data channel using
port 31746 TCP as our guide. I grep for the port number and the TCP protocol to
try to be more specific, although I could have added the source and destination
IP addresses too.

.. code-block:: console

  $ zcat 2020-08-16/conn_20200816_06\:00\:00-07\:00\:00+0000.log.gz | grep 31746 | grep tcp | sed 's/.*gz://' | jq .

::

  {
    "_path": "conn",
    "_system_name": "ds61",
    "_write_ts": "2020-08-16T06:26:09.771034Z",
    "_node": "worker-01",
    "ts": "2020-08-16T06:26:03.774520Z",
    "uid": "CzLMFA3Eh8KBlY4kS7",
    "id.orig_h": "192.168.4.76",
    "id.orig_p": 60474,
    "id.resp_h": "196.216.2.24",
    "id.resp_p": 31746,
    "proto": "tcp",
    "service": "ftp-data",
    "duration": 0.9965000152587891,
    "orig_bytes": 0,
    "resp_bytes": 74,
    "conn_state": "SF",
    "local_orig": true,
    "local_resp": false,
    "missed_bytes": 0,
    "history": "ShAdfFa",
    "orig_pkts": 4,
    "orig_ip_bytes": 216,
    "resp_pkts": 4,
    "resp_ip_bytes": 290,
    "community_id": "1:DNwvGR6Ots6pISvsdXBUIaG8y3Q="
  }

Zeek notes that this is a ``ftp-data`` service, which is another way we could
have used to find this connection.

Conclusion
==========

FTP is still in use, despite the fact that encrypted alternatives abound.
Zeek’s :file:`ftp.log` provides a compact way to summarize the salient features
of a FTP control channel, pointing out details of the control activity and how
to locate the data channel.
