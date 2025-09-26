.. _PostgreSQL protocol: https://www.postgresql.org/docs/current/protocol.html

==============
postgresql.log
==============

.. versionadded:: 7.1

Overview
========

Zeek contains a basic spicy-based `PostgreSQL protocol`_ analyzer.

Example
=======

An example of :file:`postgresql.log`.

.. code-block:: console

    $ zeek -C LogAscii::use_json=T -r psql-create-insert-select-delete-drop.pcap
    $ jq < postgresql.log
    {
      "ts": 1725368066.79174,
      "uid": "C68Wxi3EStaTmxaUVl",
      "id.orig_h": "127.0.0.1",
      "id.orig_p": 40190,
      "id.resp_h": "127.0.0.1",
      "id.resp_p": 5432,
      "user": "postgres",
      "database": "postgres",
      "application_name": "psql",
      "frontend": "simple_query",
      "frontend_arg": "CREATE TABLE IF NOT EXISTS t (i int, s varchar, t time);",
      "success": true,
      "rows": 0
    }
    {
      "ts": 1725368066.80694,
      "uid": "C68Wxi3EStaTmxaUVl",
      "id.orig_h": "127.0.0.1",
      "id.orig_p": 40190,
      "id.resp_h": "127.0.0.1",
      "id.resp_p": 5432,
      "user": "postgres",
      "database": "postgres",
      "application_name": "psql",
      "frontend": "simple_query",
      "frontend_arg": "INSERT INTO t VALUES (42, 'forty-two', now());",
      "success": true,
      "rows": 0
    }


:zeek:see:`PostgreSQL::Info` provides further details about the current output of the
:file:`postgresql.log`.

TLS
===

The PostgreSQL protocol provides a mechanism to upgrade client-server connections
to TLS. The analyzer detects this mechanism and hands off analysis to Zeek's
TLS analyzer. The :file:`postgresql.log` and :file:`conn.log` files will look
as follows:

.. code-block:: console

    $ zeek -C LogAscii::use_json=T -r testing/btest/Traces/postgresql/psql-aws-ssl-preferred.pcap
    $ jq < postgresql.log
    {
      "ts": 1670520068.267888,
      "uid": "CAcbxM1ou0N1V2cGpe",
      "id.orig_h": "192.168.123.132",
      "id.orig_p": 39910,
      "id.resp_h": "52.200.36.167",
      "id.resp_p": 5432,
      "frontend": "ssl_request",
      "backend": "ssl_reply",
      "backend_arg": "S",
      "success": true
    }

    $ jq < conn.log
    {
      "ts": 1670520068.15752,
      "uid": "CAcbxM1ou0N1V2cGpe",
      "id.orig_h": "192.168.123.132",
      "id.orig_p": 39910,
      "id.resp_h": "52.200.36.167",
      "id.resp_p": 5432,
      "proto": "tcp",
      "service": "postgresql,ssl",
      "duration": 0.931433916091919,
      "orig_bytes": 786,
      "resp_bytes": 4542,
      ...
    }
