:tocdepth: 3

base/bif/plugins/Zeek_SMTP.functions.bif.zeek
=============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
================================================ =====================================================
:zeek:id:`skip_smtp_data`: :zeek:type:`function` Skips SMTP data until the next email in a connection.
================================================ =====================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: skip_smtp_data
   :source-code: base/bif/plugins/Zeek_SMTP.functions.bif.zeek 12 12

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`) : :zeek:type:`any`

   Skips SMTP data until the next email in a connection.
   

   :param c: The SMTP connection.
   
   .. zeek:see:: skip_http_entity_data


