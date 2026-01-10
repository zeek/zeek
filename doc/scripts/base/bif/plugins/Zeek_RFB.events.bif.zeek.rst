:tocdepth: 3

base/bif/plugins/Zeek_RFB.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================================================== ==========================================================
:zeek:id:`rfb_auth_result`: :zeek:type:`event` :zeek:attr:`&deprecated` = *...* Generated for RFB event authentication result message
:zeek:id:`rfb_authentication_result`: :zeek:type:`event`                        Generated for RFB event authentication result message
:zeek:id:`rfb_authentication_type`: :zeek:type:`event`                          Generated for RFB event authentication mechanism selection
:zeek:id:`rfb_client_version`: :zeek:type:`event`                               Generated for RFB event client banner message
:zeek:id:`rfb_server_parameters`: :zeek:type:`event`                            Generated for RFB event server parameter message
:zeek:id:`rfb_server_version`: :zeek:type:`event`                               Generated for RFB event server banner message
:zeek:id:`rfb_share_flag`: :zeek:type:`event`                                   Generated for RFB event share flag messages
=============================================================================== ==========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: rfb_auth_result
   :source-code: base/bif/plugins/Zeek_RFB.events.bif.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`bool`)
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v9.1. Use rfb_authentication_result which has the correct value for result."*

   Generated for RFB event authentication result message


   :param c: The connection record for the underlying transport-layer session/flow.


   :param result: whether or not authentication was successful (false means success, true means failure)

   .. zeek:see:: rfb_authentication_result

.. zeek:id:: rfb_authentication_result
   :source-code: base/protocols/rfb/main.zeek 152 155

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`bool`)

   Generated for RFB event authentication result message


   :param c: The connection record for the underlying transport-layer session/flow.


   :param result: whether or not authentication was successful

.. zeek:id:: rfb_authentication_type
   :source-code: base/protocols/rfb/main.zeek 131 136

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, authtype: :zeek:type:`count`)

   Generated for RFB event authentication mechanism selection


   :param c: The connection record for the underlying transport-layer session/flow.


   :param authtype: the value of the chosen authentication mechanism

.. zeek:id:: rfb_client_version
   :source-code: base/protocols/rfb/main.zeek 117 122

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, major_version: :zeek:type:`string`, minor_version: :zeek:type:`string`)

   Generated for RFB event client banner message


   :param c: The connection record for the underlying transport-layer session/flow.


   :param version: of the client's rfb library

.. zeek:id:: rfb_server_parameters
   :source-code: base/bif/plugins/Zeek_RFB.events.bif.zeek 63 63

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, name: :zeek:type:`string`, width: :zeek:type:`count`, height: :zeek:type:`count`)

   Generated for RFB event server parameter message


   :param c: The connection record for the underlying transport-layer session/flow.


   :param name: name of the shared screen


   :param width: width of the shared screen


   :param height: height of the shared screen

.. zeek:id:: rfb_server_version
   :source-code: base/protocols/rfb/main.zeek 124 129

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, major_version: :zeek:type:`string`, minor_version: :zeek:type:`string`)

   Generated for RFB event server banner message


   :param c: The connection record for the underlying transport-layer session/flow.


   :param version: of the server's rfb library

.. zeek:id:: rfb_share_flag
   :source-code: base/protocols/rfb/main.zeek 157 160

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, flag: :zeek:type:`bool`)

   Generated for RFB event share flag messages


   :param c: The connection record for the underlying transport-layer session/flow.


   :param flag: whether or not the share flag was set


