:tocdepth: 3

base/bif/plugins/Bro_SMTP.functions.bif.zeek
============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
============================================== =====================================================
:bro:id:`skip_smtp_data`: :bro:type:`function` Skips SMTP data until the next email in a connection.
============================================== =====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: skip_smtp_data

   :Type: :bro:type:`function` (c: :bro:type:`connection`) : :bro:type:`any`

   Skips SMTP data until the next email in a connection.
   

   :c: The SMTP connection.
   
   .. bro:see:: skip_http_entity_data


