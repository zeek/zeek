:tocdepth: 3

base/bif/plugins/Bro_SNMP.events.bif.bro
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================== ==========================================================================
:bro:id:`snmp_encrypted_pdu`: :bro:type:`event`          An SNMPv3 encrypted PDU message.
:bro:id:`snmp_get_bulk_request`: :bro:type:`event`       An SNMP ``GetBulkRequest-PDU`` message from :rfc:`3416`.
:bro:id:`snmp_get_next_request`: :bro:type:`event`       An SNMP ``GetNextRequest-PDU`` message from either :rfc:`1157` or
                                                         :rfc:`3416`.
:bro:id:`snmp_get_request`: :bro:type:`event`            An SNMP ``GetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
:bro:id:`snmp_inform_request`: :bro:type:`event`         An SNMP ``InformRequest-PDU`` message from :rfc:`3416`.
:bro:id:`snmp_report`: :bro:type:`event`                 An SNMP ``Report-PDU`` message from :rfc:`3416`.
:bro:id:`snmp_response`: :bro:type:`event`               An SNMP ``GetResponse-PDU`` message from :rfc:`1157` or a
                                                         ``Response-PDU`` from :rfc:`3416`.
:bro:id:`snmp_set_request`: :bro:type:`event`            An SNMP ``SetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
:bro:id:`snmp_trap`: :bro:type:`event`                   An SNMP ``Trap-PDU`` message from :rfc:`1157`.
:bro:id:`snmp_trapV2`: :bro:type:`event`                 An SNMP ``SNMPv2-Trap-PDU`` message from :rfc:`1157`.
:bro:id:`snmp_unknown_header_version`: :bro:type:`event` A datagram with an unknown SNMP version.
:bro:id:`snmp_unknown_pdu`: :bro:type:`event`            An SNMP PDU message of unknown type.
:bro:id:`snmp_unknown_scoped_pdu`: :bro:type:`event`     An SNMPv3 ``ScopedPDUData`` of unknown type (neither plaintext or
                                                         an encrypted PDU was in the datagram).
======================================================== ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: snmp_encrypted_pdu

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`)

   An SNMPv3 encrypted PDU message.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.

.. bro:id:: snmp_get_bulk_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::BulkPDU`)

   An SNMP ``GetBulkRequest-PDU`` message from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_get_next_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``GetNextRequest-PDU`` message from either :rfc:`1157` or
   :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_get_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``GetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_inform_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``InformRequest-PDU`` message from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_report

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``Report-PDU`` message from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``GetResponse-PDU`` message from :rfc:`1157` or a
   ``Response-PDU`` from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_set_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``SetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_trap

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::TrapPDU`)

   An SNMP ``Trap-PDU`` message from :rfc:`1157`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_trapV2

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``SNMPv2-Trap-PDU`` message from :rfc:`1157`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_unknown_header_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, version: :bro:type:`count`)

   A datagram with an unknown SNMP version.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :version: The value of the unknown SNMP version.

.. bro:id:: snmp_unknown_pdu

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, tag: :bro:type:`count`)

   An SNMP PDU message of unknown type.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :tag: The tag of the unknown SNMP PDU.

.. bro:id:: snmp_unknown_scoped_pdu

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, tag: :bro:type:`count`)

   An SNMPv3 ``ScopedPDUData`` of unknown type (neither plaintext or
   an encrypted PDU was in the datagram).
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :tag: The tag of the unknown SNMP PDU scope.


