:tocdepth: 3

base/bif/plugins/Zeek_GSSAPI.events.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================ =========================================
:zeek:id:`gssapi_neg_result`: :zeek:type:`event` Generated for GSSAPI negotiation results.
================================================ =========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: gssapi_neg_result

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, state: :zeek:type:`count`)

   Generated for GSSAPI negotiation results.
   

   :c: The connection.
   

   :state: The resulting state of the negotiation.
   


