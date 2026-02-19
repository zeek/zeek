========
quic.log
========

.. versionadded:: 6.1

Overview
========

The QUIC protocol integrates encryption, stream multiplexing and flow control at
the transport layer. QUIC uses TLS 1.3 by default. Zeek's QUIC analyzer
provides greater observability into the protocol's TLS handshake.


Example
=======

An example of a :file:`quic.log`.

.. code-block:: console

    zeek@zeek-6.1:~ zeek -C LogAscii::use_json=T -r chromium-115.0.5790.110-api-cirrus-com.pcap
    zeek@zeek-6.1:~ jq . quic.log

::

  {
    "ts": 1692198386.837988,
    "uid": "CA482y1XJVd3d0RYI7",
    "id.orig_h": "82.239.54.117",
    "id.orig_p": 53727,
    "id.resp_h": "110.213.53.115",
    "id.resp_p": 443,
    "version": "1",
    "client_initial_dcid": "95412c47018cdfe8",
    "server_scid": "d5412c47018cdfe8",
    "server_name": "api.cirrus-ci.com",
    "client_protocol": "h3",
    "history": "ISisH"
  }


:zeek:see:`QUIC::Info` provides further details on the current output of the
:file:`quic.log`. Current fields include:

- **version**: A string interpretation of the QUIC version number, usually "1"
  or "quicv2".

- **client_initial_dcid**: When QUIC initiates a connection it uses Random
  Number Generators to create the first Destination Connection ID (DCID). This
  DCID is subsequently used for routing and packet protection by client and
  server.

- **server_scid**: A QUIC-supported server responds to a DCID by selecting a
  Source Connection ID (SCID). This usually occurs within the server’s first
  ``INITIAL`` packet. This is typically used by the client in subsequent
  packets, although the SCID can change to adapt to new network conditions.

- **client_protocol**: If the ``ClientHello`` packet is successfully extracted
  and contains the ALPN extension, the extension's first entry is placed in
  ``client_protocol``.

- **history**: Provides a history of QUIC protocol activity in a connection,
  similar to the history fields in conn.log and ssh.log. See the
  :zeek:see:`QUIC::Info` documentation for details. In the example above,
  the history outlines:

    + An initial packet from the client (I) - a new connection

    + An TLS ``ClientHello`` from the client (S) - the start of a
      TLS handshake

    + An initial packet from the server (i) - an acknowledgement
      from the server of the new connection

    + A TLS ServerHello response from the server (s) - the
      selection of a cipher suite from the options provided by the
      client

    + A handshake packet from the client (H)


Conclusion
==========

The QUIC analyzer provides some observability into QUIC network traffic,
particularly around connection establishment. Introduced in version 6.1, it's
one of Zeek's newer parsers, so feedback is particularly welcome.
