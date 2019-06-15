:tocdepth: 3

base/bif/plugins/Zeek_SNMP.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================== ==========================================================================
:zeek:id:`snmp_encrypted_pdu`: :zeek:type:`event`          An SNMPv3 encrypted PDU message.
:zeek:id:`snmp_get_bulk_request`: :zeek:type:`event`       An SNMP ``GetBulkRequest-PDU`` message from :rfc:`3416`.
:zeek:id:`snmp_get_next_request`: :zeek:type:`event`       An SNMP ``GetNextRequest-PDU`` message from either :rfc:`1157` or
                                                           :rfc:`3416`.
:zeek:id:`snmp_get_request`: :zeek:type:`event`            An SNMP ``GetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
:zeek:id:`snmp_inform_request`: :zeek:type:`event`         An SNMP ``InformRequest-PDU`` message from :rfc:`3416`.
:zeek:id:`snmp_report`: :zeek:type:`event`                 An SNMP ``Report-PDU`` message from :rfc:`3416`.
:zeek:id:`snmp_response`: :zeek:type:`event`               An SNMP ``GetResponse-PDU`` message from :rfc:`1157` or a
                                                           ``Response-PDU`` from :rfc:`3416`.
:zeek:id:`snmp_set_request`: :zeek:type:`event`            An SNMP ``SetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
:zeek:id:`snmp_trap`: :zeek:type:`event`                   An SNMP ``Trap-PDU`` message from :rfc:`1157`.
:zeek:id:`snmp_trapV2`: :zeek:type:`event`                 An SNMP ``SNMPv2-Trap-PDU`` message from :rfc:`1157`.
:zeek:id:`snmp_unknown_header_version`: :zeek:type:`event` A datagram with an unknown SNMP version.
:zeek:id:`snmp_unknown_pdu`: :zeek:type:`event`            An SNMP PDU message of unknown type.
:zeek:id:`snmp_unknown_scoped_pdu`: :zeek:type:`event`     An SNMPv3 ``ScopedPDUData`` of unknown type (neither plaintext or
                                                           an encrypted PDU was in the datagram).
========================================================== ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: snmp_encrypted_pdu

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`)

   An SNMPv3 encrypted PDU message.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.

.. zeek:id:: snmp_get_bulk_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::BulkPDU`)

   An SNMP ``GetBulkRequest-PDU`` message from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_get_next_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``GetNextRequest-PDU`` message from either :rfc:`1157` or
   :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_get_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``GetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_inform_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``InformRequest-PDU`` message from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_report

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``Report-PDU`` message from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``GetResponse-PDU`` message from :rfc:`1157` or a
   ``Response-PDU`` from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_set_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``SetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_trap

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::TrapPDU`)

   An SNMP ``Trap-PDU`` message from :rfc:`1157`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_trapV2

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``SNMPv2-Trap-PDU`` message from :rfc:`1157`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_unknown_header_version

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`)

   A datagram with an unknown SNMP version.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :version: The value of the unknown SNMP version.

.. zeek:id:: snmp_unknown_pdu

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, tag: :zeek:type:`count`)

   An SNMP PDU message of unknown type.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :tag: The tag of the unknown SNMP PDU.

.. zeek:id:: snmp_unknown_scoped_pdu

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, tag: :zeek:type:`count`)

   An SNMPv3 ``ScopedPDUData`` of unknown type (neither plaintext or
   an encrypted PDU was in the datagram).
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :tag: The tag of the unknown SNMP PDU scope.


