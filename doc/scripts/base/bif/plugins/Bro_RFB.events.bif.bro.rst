:tocdepth: 3

base/bif/plugins/Bro_RFB.events.bif.bro
=======================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================== ==========================================================
:bro:id:`rfb_auth_result`: :bro:type:`event`         Generated for RFB event authentication result message
:bro:id:`rfb_authentication_type`: :bro:type:`event` Generated for RFB event authentication mechanism selection
:bro:id:`rfb_client_version`: :bro:type:`event`      Generated for RFB event client banner message
:bro:id:`rfb_event`: :bro:type:`event`               Generated for RFB event
:bro:id:`rfb_server_parameters`: :bro:type:`event`   Generated for RFB event server parameter message
:bro:id:`rfb_server_version`: :bro:type:`event`      Generated for RFB event server banner message
:bro:id:`rfb_share_flag`: :bro:type:`event`          Generated for RFB event share flag messages
==================================================== ==========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: rfb_auth_result

   :Type: :bro:type:`event` (c: :bro:type:`connection`, result: :bro:type:`bool`)

   Generated for RFB event authentication result message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :result: whether or not authentication was succesful

.. bro:id:: rfb_authentication_type

   :Type: :bro:type:`event` (c: :bro:type:`connection`, authtype: :bro:type:`count`)

   Generated for RFB event authentication mechanism selection
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :authtype: the value of the chosen authentication mechanism

.. bro:id:: rfb_client_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, major_version: :bro:type:`string`, minor_version: :bro:type:`string`)

   Generated for RFB event client banner message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :version: of the client's rfb library

.. bro:id:: rfb_event

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for RFB event
   

   :c: The connection record for the underlying transport-layer session/flow.

.. bro:id:: rfb_server_parameters

   :Type: :bro:type:`event` (c: :bro:type:`connection`, name: :bro:type:`string`, width: :bro:type:`count`, height: :bro:type:`count`)

   Generated for RFB event server parameter message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :name: name of the shared screen
   

   :width: width of the shared screen
   

   :height: height of the shared screen

.. bro:id:: rfb_server_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, major_version: :bro:type:`string`, minor_version: :bro:type:`string`)

   Generated for RFB event server banner message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :version: of the server's rfb library

.. bro:id:: rfb_share_flag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, flag: :bro:type:`bool`)

   Generated for RFB event share flag messages
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :flag: whether or not the share flag was set


