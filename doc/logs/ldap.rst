============================
ldap.log and ldap_search.log
============================

.. versionadded:: 6.1

The Lightweight Directory Access Protocol (LDAP) is a
widely observed protocol commonly used for authenticating, directory lookups,
centralizing organisational information and accessing client information on
email servers. Accordingly, the protocol attracts significant attention from
those with adversarial intention.


LDAP Protocol Overview
======================

LDAP communicates using a client-server model. The LDAP server contains the
directory information and the LDAP client performs operations against this
information. This is a quick overview of how the protocol works:

    Sessions: An LDAP session begins with a client connecting to an LDAP server,
    optionally securing the connection with encryption, and then binding to the
    server by providing credentials.

    Queries: Clients search for entries in the LDAP directory using LDAP
    queries, which consist of a base Distinguished Name (DN), a scope (such
    as one level or the entire subtree), and a filter to match entries. Queries
    are read only.

    Operations: Clients with the correct privileges can perform a variety of
    operations; in addition to search, they can add, delete or modify.

    Data Format: LDAP data entries are formatted as records consisting of a
    DN and a set of attributes. Each attribute has a name and one or more values.

The LDAP analyzer outputs two LDAP related logs. :file:`ldap.log` contains
details about the LDAP session except those related to searches.
:file:`ldap_search.log` contains information related to LDAP searches.

For details on every element of the :file:`ldap.log` and :file:`ldap_search.log`
refer to :zeek:see:`LDAP::MessageInfo` and :zeek:see:`LDAP::SearchInfo`, respectively.
Below is an inspection of the :file:`ldap.log` and :file:`ldap_search.log` in JSON format.

ldap.log
========

An example of an :file:`ldap.log`.

.. code-block:: console

    zeek@zeek-6.1:~ zeek -C LogAscii::use_json=T LDAP::default_log_search_attributes=T -r ldap-simpleauth.pcap
    zeek@zeek-6.1:~ jq . ldap.log

::

    {
      "ts": 1463256456.051759,
      "uid": "ChD43F3guxAmJ5f2aj",
      "id.orig_h": "10.0.0.1",
      "id.orig_p": 25936,
      "id.resp_h": "10.0.0.2",
      "id.resp_p": 3268,
      "message_id": 3,
      "version": 3,
      "opcode": "bind simple",
      "result": "success",
      "object": "CN=xxxxxxxx,OU=Users,OU=Accounts,DC=xx,DC=xxx,DC=xxxxx,DC=net",
      "argument": "REDACTED"
    }


ldap_search.log
===============

An example of an :file:`ldap_search.log`. Note the default for
:zeek:see:`LDAP::default_log_search_attributes` is F, excluding attributes
from the log.

.. code-block:: console

    zeek@zeek-6.1:~ zeek -C LogAscii::use_json=T LDAP::default_log_search_attributes=T -r ldap-simpleauth.pcap
    zeek@zeek-6.1:~ jq . ldap_search.log

::

    {
      "ts": 1463256456.047579,
      "uid": "CAOF1l3FR8UzQ7mIb8",
      "id.orig_h": "10.0.0.1",
      "id.orig_p": 25936,
      "id.resp_h": "10.0.0.2",
      "id.resp_p": 3268,
      "message_id": 2,
      "scope": "tree",
      "deref_aliases": "always",
      "base_object": "DC=xx,DC=xxx,DC=xxxxx,DC=net",
      "result_count": 1,
      "result": "success",
      "filter": "(&(objectclass=*)(sAMAccountName=xxxxxxxx))",
      "attributes": [
        "sAMAccountName"
      ]
    }


Conclusion
==========

The Zeek LDAP logs provide additional insights that help improve observability
into this protocol.
