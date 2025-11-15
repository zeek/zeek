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
   :source-code: base/protocols/snmp/main.zeek 186 189

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`)

   An SNMPv3 encrypted PDU message.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.

.. zeek:id:: snmp_get_bulk_request
   :source-code: base/protocols/snmp/main.zeek 119 123

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::BulkPDU`)

   An SNMP ``GetBulkRequest-PDU`` message from :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_get_next_request
   :source-code: base/protocols/snmp/main.zeek 125 129

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``GetNextRequest-PDU`` message from either :rfc:`1157` or
   :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_get_request
   :source-code: base/protocols/snmp/main.zeek 113 117

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``GetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_inform_request
   :source-code: base/protocols/snmp/main.zeek 161 164

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``InformRequest-PDU`` message from :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_report
   :source-code: base/protocols/snmp/main.zeek 171 174

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``Report-PDU`` message from :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_response
   :source-code: base/protocols/snmp/main.zeek 131 148

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``GetResponse-PDU`` message from :rfc:`1157` or a
   ``Response-PDU`` from :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_set_request
   :source-code: base/protocols/snmp/main.zeek 150 154

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``SetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_trap
   :source-code: base/protocols/snmp/main.zeek 156 159

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::TrapPDU`)

   An SNMP ``Trap-PDU`` message from :rfc:`1157`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_trapV2
   :source-code: base/protocols/snmp/main.zeek 166 169

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``SNMPv2-Trap-PDU`` message from :rfc:`1157`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_unknown_header_version
   :source-code: base/bif/plugins/Zeek_SNMP.events.bif.zeek 168 168

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`)

   A datagram with an unknown SNMP version.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param version: The value of the unknown SNMP version.

.. zeek:id:: snmp_unknown_pdu
   :source-code: base/protocols/snmp/main.zeek 176 179

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, tag: :zeek:type:`count`)

   An SNMP PDU message of unknown type.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param tag: The tag of the unknown SNMP PDU.

.. zeek:id:: snmp_unknown_scoped_pdu
   :source-code: base/protocols/snmp/main.zeek 181 184

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, tag: :zeek:type:`count`)

   An SNMPv3 ``ScopedPDUData`` of unknown type (neither plaintext or
   an encrypted PDU was in the datagram).
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param tag: The tag of the unknown SNMP PDU scope.


