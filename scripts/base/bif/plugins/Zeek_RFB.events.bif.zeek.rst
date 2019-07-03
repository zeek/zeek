:tocdepth: 3

base/bif/plugins/Zeek_RFB.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================================================================================================================================================== ==========================================================
:zeek:id:`rfb_auth_result`: :zeek:type:`event`                                                                                                                                                 Generated for RFB event authentication result message
:zeek:id:`rfb_authentication_type`: :zeek:type:`event`                                                                                                                                         Generated for RFB event authentication mechanism selection
:zeek:id:`rfb_client_version`: :zeek:type:`event`                                                                                                                                              Generated for RFB event client banner message
:zeek:id:`rfb_event`: :zeek:type:`event` :zeek:attr:`&deprecated` = ``"Remove in v3.1: This event never served a real purpose and will be removed. Please use the other rfb events instead."`` Generated for RFB event
:zeek:id:`rfb_server_parameters`: :zeek:type:`event`                                                                                                                                           Generated for RFB event server parameter message
:zeek:id:`rfb_server_version`: :zeek:type:`event`                                                                                                                                              Generated for RFB event server banner message
:zeek:id:`rfb_share_flag`: :zeek:type:`event`                                                                                                                                                  Generated for RFB event share flag messages
============================================================================================================================================================================================== ==========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: rfb_auth_result

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`bool`)

   Generated for RFB event authentication result message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :result: whether or not authentication was succesful

.. zeek:id:: rfb_authentication_type

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, authtype: :zeek:type:`count`)

   Generated for RFB event authentication mechanism selection
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :authtype: the value of the chosen authentication mechanism

.. zeek:id:: rfb_client_version

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, major_version: :zeek:type:`string`, minor_version: :zeek:type:`string`)

   Generated for RFB event client banner message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :version: of the client's rfb library

.. zeek:id:: rfb_event

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)
   :Attributes: :zeek:attr:`&deprecated` = ``"Remove in v3.1: This event never served a real purpose and will be removed. Please use the other rfb events instead."``

   Generated for RFB event
   

   :c: The connection record for the underlying transport-layer session/flow.

.. zeek:id:: rfb_server_parameters

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, name: :zeek:type:`string`, width: :zeek:type:`count`, height: :zeek:type:`count`)

   Generated for RFB event server parameter message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :name: name of the shared screen
   

   :width: width of the shared screen
   

   :height: height of the shared screen

.. zeek:id:: rfb_server_version

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, major_version: :zeek:type:`string`, minor_version: :zeek:type:`string`)

   Generated for RFB event server banner message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :version: of the server's rfb library

.. zeek:id:: rfb_share_flag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, flag: :zeek:type:`bool`)

   Generated for RFB event share flag messages
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :flag: whether or not the share flag was set


