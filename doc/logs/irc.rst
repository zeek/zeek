=======
irc.log
=======

Internet Relay Chat (IRC) is an older protocol that enables real time chat and
collaboration. The Zeek project hosted an IRC channel for many years to support
development and discussion. Some intruders eventually began using IRC to
control botnets, primarily for two reasons. First, as IRC had legitimate uses,
it may not have been suspicious or malicious to see IRC traffic on the wire.
Second, IRC enabled command-and-control, thanks to the ability for operators to
issue instructions to clients that controlled compromised systems.

Traditionally, IRC clients connect via a clear-text TCP session to an IRC
server listening on port 6667. The commands and responses are text-based,
making it possible for an analyst to manually inspect them. More recent
implementations of IRC servers offer IRC over TLS, with the servers listening
on port 6697 TCP. However, for both unencrypted or encrypted sessions, IRC
servers can listen on any TCP port.

For full details on each field in the :file:`irc.log` file, please see
:zeek:see:`IRC::Info`.

Reconstructing an IRC Session
=============================

Before examining the data provided by Zeek’s :file:`irc.log`, it might be
useful to see the contents of an IRC session. I generated the following
activity using the Hexchat IRC client.

I have edited the transcript to focus on essential items. Text in bold was sent
by the IRC client. The server sent the remaining text.

.. literal-emph::

  **CAP LS 302**
  :barjavel.freenode.net NOTICE * :*** Looking up your hostname...
  **NICK zeektest**
  **USER zeektest 0 * :realname**
  :barjavel.freenode.net NOTICE * :*** Checking Ident
  :barjavel.freenode.net NOTICE * :*** Found your hostname
  :barjavel.freenode.net NOTICE * :*** No Ident response
  :barjavel.freenode.net CAP * LS :account-notify away-notify cap-notify chghost extended-join identify-msg multi-prefix sasl tls
  **CAP REQ :account-notify away-notify cap-notify chghost extended-join identify-msg multi-prefix**
  **:barjavel.freenode.net CAP zeektest ACK :account-notify away-notify cap-notify chghost extended-join identify-msg multi-prefix **
  **CAP END**
  :barjavel.freenode.net 001 zeektest :Welcome to the freenode Internet Relay Chat Network zeektest
  :barjavel.freenode.net 002 zeektest :Your host is barjavel.freenode.net[195.154.200.232/6667], running version ircd-seven-1.1.9
  :barjavel.freenode.net 003 zeektest :This server was created Thu Dec 19 2019 at 20:10:02 UTC
  :barjavel.freenode.net 004 zeektest barjavel.freenode.net ircd-seven-1.1.9 DOQRSZaghilopsuwz CFILMPQSbcefgijklmnopqrstuvz bkloveqjfI
  :barjavel.freenode.net 005 zeektest CHANTYPES=# EXCEPTS INVEX CHANMODES=eIbq,k,flj,CFLMPQScgimnprstuz CHANLIMIT=#:120 PREFIX=(ov)@+ MAXLIST=bqeI:100 MODES=4 NETWORK=freenode STATUSMSG=@+ CALLERID=g CASEMAPPING=rfc1459 :are supported by this server
  :barjavel.freenode.net 005 zeektest CHARSET=ascii NICKLEN=16 CHANNELLEN=50 TOPICLEN=390 DEAF=D FNC TARGMAX=NAMES:1,LIST:1,KICK:1,WHOIS:1,PRIVMSG:4,NOTICE:4,ACCEPT:,MONITOR: EXTBAN=$,ajrxz CLIENTVER=3.0 WHOX KNOCK CPRIVMSG :are supported by this server
  :barjavel.freenode.net 005 zeektest CNOTICE ETRACE SAFELIST ELIST=CTU MONITOR=100 :are supported by this server
  :barjavel.freenode.net 251 zeektest :There are 101 users and 82081 invisible on 31 servers
  :barjavel.freenode.net 252 zeektest 43 :IRC Operators online
  :barjavel.freenode.net 253 zeektest 45 :unknown connection(s)
  :barjavel.freenode.net 254 zeektest 41982 :channels formed
  :barjavel.freenode.net 255 zeektest :I have 3809 clients and 1 servers
  :barjavel.freenode.net 265 zeektest 3809 5891 :Current local users 3809, max 5891
  :barjavel.freenode.net 266 zeektest 82182 90930 :Current global users 82182, max 90930
  :barjavel.freenode.net 250 zeektest :Highest connection count: 5892 (5891 clients) (1543159 connections received)
  :barjavel.freenode.net 375 zeektest :- barjavel.freenode.net Message of the Day - 
  :barjavel.freenode.net 372 zeektest :- Welcome to barjavel.freenode.net in Paris, FR, EU. 
  ...edited…
  :barjavel.freenode.net 372 zeektest :- Thank you for using freenode!
  :barjavel.freenode.net 376 zeektest :End of /MOTD command.
  :zeektest MODE zeektest :+i
  **JOIN #freenode**
  :zeektest!~zeektest@pool-XX-XXX-XXX-XX.washdc.fios.verizon.net JOIN #freenode * :realname
  :barjavel.freenode.net 332 zeektest #freenode :Welcome to #freenode | Don't copy/paste spam | No politics. | Feel free to message staff at any time. You can find us using /stats p (shows immediately-available staff) or /who freenode/staff/* (shows all staff)
  :barjavel.freenode.net 333 zeektest #freenode deadk 1604191950
  ...edited…
  :ChanServ!ChanServ@services. NOTICE zeektest :+[#freenode] Please read the topic.
  :services. 328 zeektest #freenode :https://freenode.net/
  **WHO #freenode %chtsunfra,152**
  :barjavel.freenode.net 324 zeektest #freenode +CLPcntjf 5:10 #freenode-overflow
  ...edited…
  **PING LAG641756037**
  :barjavel.freenode.net PONG barjavel.freenode.net :LAG641756037
  :willcl_ark!~quassel@cpc123780-trow7-2-0-cust177.18-1.cable.virginm.net AWAY :Away
  :EGH!~EGH@79.142.76.202 JOIN #freenode EGH :Erik
  **PRIVMSG #freenode :One more test... thanks everyone.**
  **QUIT :Leaving**
  :zeektest!~zeektest@pool-XX-XXX-XXX-XX.washdc.fios.verizon.net QUIT :Client Quit
  ERROR :Closing Link: pool-XX-XXX-XXX-XX.washdc.fios.verizon.net (Client Quit)

As you can see, there is a lot of detail about the IRC server and the channels
and users it supports. The client uses the nickname ``zeektest`` and joins the
``#freenode`` channel. It issues one message. ``One more test… thanks
everyone``, and then quits.

I captured this traffic by manually setting disabling TLS. Otherwise, the
protocol exchange would have been opaque to Zeek (and other NSM tools).

With this basic background on IRC, let’s see how Zeek renders this activity.

Port 6667 :file:`conn.log`
==========================

Zeek generated the following :file:`conn.log` entry for the example traffic.

.. literal-emph::

  {
    "ts": 1607009493.558305,
    "uid": "CDsHGC2ZJuJh10XNbk",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 52856,
    "id.resp_h": "195.154.200.232",
    **"id.resp_p": 6667,**
    **"proto": "tcp",**
    **"service": "irc",**
    "duration": 55.26594305038452,
    "orig_bytes": 311,
    "resp_bytes": 239330,
    "conn_state": "RSTO",
    "missed_bytes": 0,
    "history": "ShADadfR",
    "orig_pkts": 41,
    "orig_ip_bytes": 1963,
    "resp_pkts": 185,
    "resp_ip_bytes": 246742
  }

We see that Zeek correctly identified this traffic as IRC. We can expect to see
an :file:`irc.log` entry.

Port 6667 :file:`irc.log`
=========================

Zeek generated the following three :file:`irc.log` entries:

.. literal-emph::

  {
    "ts": 1607009493.733304,
    "uid": "CDsHGC2ZJuJh10XNbk",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 52856,
    "id.resp_h": "195.154.200.232",
    "id.resp_p": 6667,
    **"command": "NICK",**
    **"value": "zeektest"**
  }
  {
    "ts": 1607009493.733304,
    "uid": "CDsHGC2ZJuJh10XNbk",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 52856,
    "id.resp_h": "195.154.200.232",
    "id.resp_p": 6667,
    **"nick": "zeektest",**
    **"command": "USER",**
    **"value": "zeektest",**
    "addl": "0 * realname"
  }
  {
    "ts": 1607009514.481161,
    "uid": "CDsHGC2ZJuJh10XNbk",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 52856,
    "id.resp_h": "195.154.200.232",
    "id.resp_p": 6667,
    **"nick": "zeektest",**
    **"user": "zeektest",**
    **"command": "JOIN",**
    **"value": "#freenode",**
    "addl": ""
  }

We see that Zeek collected information on three aspects of the IRC activity. It
captured the setting of the NICK and USER values, as well as a JOIN command.

Looking at the Zeek scripting reference, it looks like Zeek will also track
Direct Client-to-Client (or Direct Client Connection, also known as DCC)
activity, usually used to exchange files via IRC.

Now that we know what a traditional unencrypted IRC session looks like, let’s
see how a modern TLS-encrypted IRC session appears.

Port 6697 :file:`conn.log`
==========================

Running Zeek against a capture of IRC over TLS, Zeek produces the following
:file:`conn.log` entry.

.. literal-emph::

  {
    "ts": 1607009173.307125,
    "uid": "CxLRXG3BJ8KYCW6flg",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 59423,
    "id.resp_h": "185.30.166.38",
    **"id.resp_p": 6697,**
    **"proto": "tcp",**
    **"service": "ssl",**
    "duration": 80.66936779022217,
    "orig_bytes": 1162,
    "resp_bytes": 251941,
    "conn_state": "RSTR",
    "missed_bytes": 0,
    "history": "ShADadfr",
    "orig_pkts": 49,
    "orig_ip_bytes": 3134,
    "resp_pkts": 197,
    "resp_ip_bytes": 259833
  }

Here we see that Zeek only knows that it is looking at a TLS session.

Port 6697 :file:`ssl.log` and :file:`x509.log`
==============================================

Because this traffic is encrypted via TLS, Zeek produced :file:`ssl.log` and
:file:`x509.log` entries.

First, let’s look at :file:`ssl.log`:

.. literal-emph::

  {
    "ts": 1607009173.826036,
    "uid": "CxLRXG3BJ8KYCW6flg",
    "id.orig_h": "192.168.4.142",
    "id.orig_p": 59423,
    "id.resp_h": "185.30.166.38",
    "id.resp_p": 6697,
    "version": "TLSv12",
    "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "curve": "secp256r1",
    **"server_name": "chat.freenode.net",**
    "resumed": false,
    "established": true,
    "cert_chain_fuids": [
      "F6pDkA4niQwyXPxugf",
      "F1JGJ81fmUN17LOYnk"
    ],
    "client_cert_chain_fuids": [],
    **"subject": "CN=verne.freenode.net",**
    "issuer": "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US"
  }

The references to Freenode and ``chat`` can help clue an analyst to the
likelihood that the client is engaging in IRC sessions.

Now let’s look at the :file:`x509.log`:

.. literal-emph::

  {
    "ts": 1607009173.828159,
    "id": "F6pDkA4niQwyXPxugf",
    "certificate.version": 3,
    "certificate.serial": "040831FAE9EF9E4D666A4B9EDE996878C79B",
    "certificate.subject": "CN=verne.freenode.net",
    "certificate.issuer": "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
    "certificate.not_valid_before": 1605501336,
    "certificate.not_valid_after": 1613277336,
    "certificate.key_alg": "rsaEncryption",
    "certificate.sig_alg": "sha256WithRSAEncryption",
    "certificate.key_type": "rsa",
    "certificate.key_length": 4096,
    "certificate.exponent": "65537",
    "san.dns": [
      **"chat.au.freenode.com",**
      **"chat.au.freenode.net",**
      **"chat.au.freenode.org",**
      **"chat.eu.freenode.com",**
      **"chat.eu.freenode.net",**
      **"chat.eu.freenode.org",**
      **"chat.freenode.com",**
      **"chat.freenode.net",**
      **"chat.freenode.org",**
      **"chat.ipv4.freenode.com",**
      **"chat.ipv4.freenode.net",**
      **"chat.ipv4.freenode.org",**
      **"chat.ipv6.freenode.com",**
      **"chat.ipv6.freenode.net",**
      **"chat.ipv6.freenode.org",**
      **"chat.us.freenode.com",**
      **"chat.us.freenode.net",**
      **"chat.us.freenode.org",**
      **"ipv6.chat.freenode.net",**
      **"ipv6.irc.freenode.net",**
      **"irc.au.freenode.com",**
      **"irc.au.freenode.net",**
      **"irc.au.freenode.org",**
      **"irc.eu.freenode.com",**
      **"irc.eu.freenode.net",**
      **"irc.eu.freenode.org",**
      **"irc.freenode.com",**
      **"irc.freenode.net",**
      **"irc.freenode.org",**
      **"irc.ipv4.freenode.com",**
      **"irc.ipv4.freenode.net",**
      **"irc.ipv4.freenode.org",**
      **"irc.ipv6.freenode.com",**
      **"irc.ipv6.freenode.net",**
      **"irc.ipv6.freenode.org",**
      **"irc.us.freenode.com",**
      **"irc.us.freenode.net",**
      **"irc.us.freenode.org",**
      **"verne.freenode.net"**
    ],
    "basic_constraints.ca": false
  }
  {
    "ts": 1607009173.828159,
    "id": "F1JGJ81fmUN17LOYnk",
    "certificate.version": 3,
    "certificate.serial": "0A0141420000015385736A0B85ECA708",
    "certificate.subject": "CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US",
    "certificate.issuer": "CN=DST Root CA X3,O=Digital Signature Trust Co.",
    "certificate.not_valid_before": 1458232846,
    "certificate.not_valid_after": 1615999246,
    "certificate.key_alg": "rsaEncryption",
    "certificate.sig_alg": "sha256WithRSAEncryption",
    "certificate.key_type": "rsa",
    "certificate.key_length": 2048,
    "certificate.exponent": "65537",
    "basic_constraints.ca": true,
    "basic_constraints.path_len": 0
  }

The bolded entries containing strings with “IRC”, “chat”, and Freenode are
again clues that IRC is in play here.

Port 31337 :file:`conn.log`
===========================

Here is a different session where port 31337 TCP offered clear-text IRC
connections. Zeek produced three :file:`conn.log` entries, involving clients
with IP addresses of ``10.240.0.3``, ``10.240.0.4``, and ``10.240.0.5``. Here
is an entry for the client ``10.240.0.5``.

.. literal-emph::

  {
    "ts": 1461774814.057057,
    "uid": "Cs0hwm3slMw4IBDU0h",
    "id.orig_h": "10.240.0.5",
    "id.orig_p": 42277,
    "id.resp_h": "10.240.0.2",
    **"id.resp_p": 31337,**
    **"proto": "tcp",**
    **"service": "irc",**
    "duration": 787.9501581192017,
    "orig_bytes": 1026,
    "resp_bytes": 10425,
    "conn_state": "SF",
    "missed_bytes": 0,
    "history": "ShADadfF",
    "orig_pkts": 95,
    "orig_ip_bytes": 5974,
    "resp_pkts": 87,
    "resp_ip_bytes": 14957
  }

Zeek identified the protocol as IRC by using its dynamic port detection
functionality. It did not need to see IRC on port 6667 TCP in order to
recognize the protocol.

Port 31337 :file:`irc.log`
==========================

Zeek produced many entries in the :file:`irc.log` for this activity, so I
extracted the key values.

.. code-block:: console

  $ jq -c '[."id.orig_h", ."nick", ."user", ."command", ."value", ."addl"]' irc.log

::

  ["10.240.0.3",null,null,"NICK","Matir",null]
  ["10.240.0.3","Matir",null,"USER","root-poppopret","root-poppopret 10.240.0.2 matir"]
  ["10.240.0.3","Matir","root-poppopret","JOIN","#ctf",""]
  ["10.240.0.4",null,null,"NICK","andrewg",null]
  ["10.240.0.4","andrewg",null,"USER","root-poppopret","root-poppopret 10.240.0.2 andrewg"]
  ["10.240.0.4","andrewg","root-poppopret","JOIN","#ctf",""]
  ["10.240.0.5",null,null,"NICK","itsl0wk3y",null]
  ["10.240.0.5","itsl0wk3y",null,"USER","root-poppopret","root-poppopret 10.240.0.2 l0w"]
  ["10.240.0.5","itsl0wk3y","root-poppopret","JOIN","#ctf",""]

As with the previous :file:`irc.log`, you can see elements like the nickname,
username, commands, and additional data for the connections. You do not see any
details of what users said to each other.

Botnet IRC Traffic
==================

The following example is an excerpt from a case provided by the Malware Capture
Facility, a sister project to the Stratosphere IPS Project. The case is
CTU-IoT-Malware-Capture-3-1, located here:

https://mcfp.felk.cvut.cz/publicDatasets/IoTDatasets/CTU-IoT-Malware-Capture-3-1/

The case includes IRC traffic caused by systems compromised and under the
control of the Muhstihk botnet. More details are available in this blog post:

https://blog.netlab.360.com/botnet-muhstik-is-actively-exploiting-drupal-cve-2018-7600-in-a-worm-style-en/

Here is a summary of the conn.log for the malicious IRC traffic.

.. code-block:: console

  $ jq -c '[."id.orig_h", ."id.resp_h", ."id.resp_p", ."proto", ."service"]' conn.log

::

  ["192.168.2.5","111.230.241.23",2407,"tcp","irc"]
  ["192.168.2.5","51.38.81.99",2407,"tcp","irc"]
  ["192.168.2.5","185.61.149.22",2407,"tcp",null]
  ["192.168.2.5","54.39.23.28",2407,"tcp","irc"]
  ["192.168.2.5","54.39.23.28",2407,"tcp","irc"]
  ["192.168.2.5","185.47.129.56",2407,"tcp",null]
  ["213.140.50.114","192.168.2.5",1,"icmp",null]
  ["192.168.2.5","111.230.241.23",2407,"tcp","irc"]
  ["192.168.2.5","54.39.23.28",2407,"tcp","irc"]

We see the victim, ``192.168.2.5``, connecting to multiple IRC servers on port
2407 TCP. Note that Zeek does not recognize all of the IRC traffic using its
IRC protocol analyzer. Zeek does see six IRC sessions that it parses in the
:file:`irc.log`.

Here is a summary of the :file:`irc.log` for the IRC traffic created by this
botnet client.

.. code-block:: console

  $ jq -c '[."id.orig_h", ."id.resp_h", ."nick", ."user", ."command", ."value", ."addl"]' irc.log

::

  ["192.168.2.5","111.230.241.23",null,null,"NICK","A5|1|5358668|black-pe",null]
  ["192.168.2.5","111.230.241.23","A5|1|5358668|black-pe",null,"USER","muhstik","localhost localhost muhstik-11052018"]
  ["192.168.2.5","51.38.81.99",null,null,"NICK","A5|1|5358668|black-pe",null]
  ["192.168.2.5","51.38.81.99","A5|1|5358668|black-pe",null,"USER","muhstik","localhost localhost muhstik-11052018"]
  ["192.168.2.5","51.38.81.99","A5|1|5358668|black-pe","muhstik","JOIN","#a925d765"," with channel key: ':8974'"]
  ["192.168.2.5","54.39.23.28",null,null,"NICK","A5|1|5358668|black-pe",null]
  ["192.168.2.5","54.39.23.28","A5|1|5358668|black-pe",null,"USER","muhstik","localhost localhost muhstik-11052018"]
  ["192.168.2.5","54.39.23.28","A5|1|5358668|black-pe","muhstik","JOIN","#a925d765"," with channel key: ':8974'"]
  ["192.168.2.5","54.39.23.28",null,null,"NICK","A5|1|5358668|black-pe",null]
  ["192.168.2.5","54.39.23.28","A5|1|5358668|black-pe",null,"USER","muhstik","localhost localhost muhstik-11052018"]
  ["192.168.2.5","54.39.23.28","A5|1|5358668|black-pe","muhstik","JOIN","#a925d765"," with channel key: ':8974'"]
  ["192.168.2.5","111.230.241.23",null,null,"NICK","A5|1|5358668|black-pe",null]
  ["192.168.2.5","111.230.241.23","A5|1|5358668|black-pe",null,"USER","muhstik","localhost localhost muhstik-11052018"]
  ["192.168.2.5","111.230.241.23","A5|1|5358668|black-pe","muhstik","JOIN","#a925d765"," with channel key: ':8974'"]
  ["192.168.2.5","54.39.23.28",null,null,"NICK","A5|1|5358668|black-pe",null]
  ["192.168.2.5","54.39.23.28","A5|1|5358668|black-pe",null,"USER","muhstik","localhost localhost muhstik-11052018"]
  ["192.168.2.5","54.39.23.28","A5|1|5358668|black-pe","muhstik","JOIN","#a925d765"," with channel key: ':8974'"]

Here is an example transcript for one of the IRC sessions:

.. literal-emph::

  **NICK A5|1|5358668|black-pe**
  **USER muhstik localhost localhost :muhstik-11052018**
  PING :A2A5630
  **PONG :A2A5630**
  :x4.tipu 010 A5|1|5358668|black-pe x4.tipu 0
  :x4.tipu 010 A5|1|5358668|black-pe pomf 6667
  ERROR :Closing Link: A5|1|5358668|black-pe[109.81.208.168] (This server is full.)

Thankfully for the analyst, it declares itself using the easily-searchable name
``muhstik``. This makes it easy to do open source research and identify the
malicious nature of the activity.

Conclusion
==========

Security analysts may still encounter IRC when botnets and other malware use it
for command-and-control. As other forms of modern collaboration and chat have
become prevalent, the normality of IRC has become a remnant of a bygone era.
