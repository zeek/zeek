:tocdepth: 3

base/bif/plugins/Bro_GSSAPI.events.bif.zeek
===========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================== =========================================
:bro:id:`gssapi_neg_result`: :bro:type:`event` Generated for GSSAPI negotiation results.
============================================== =========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: gssapi_neg_result

   :Type: :bro:type:`event` (c: :bro:type:`connection`, state: :bro:type:`count`)

   Generated for GSSAPI negotiation results.
   

   :c: The connection.
   

   :state: The resulting state of the negotiation.
   


