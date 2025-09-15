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
   :source-code: base/bif/plugins/Zeek_GSSAPI.events.bif.zeek 10 10

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, state: :zeek:type:`count`)

   Generated for GSSAPI negotiation results.
   

   :param c: The connection.
   

   :param state: The resulting state of the negotiation.
   


