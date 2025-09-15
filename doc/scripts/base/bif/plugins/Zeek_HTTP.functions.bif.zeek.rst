:tocdepth: 3

base/bif/plugins/Zeek_HTTP.functions.bif.zeek
=============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
======================================================= ===============================================================
:zeek:id:`skip_http_entity_data`: :zeek:type:`function` Skips the data of the HTTP entity.
:zeek:id:`unescape_URI`: :zeek:type:`function`          Unescapes all characters in a URI (decode every ``%xx`` group).
======================================================= ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: skip_http_entity_data
   :source-code: base/bif/plugins/Zeek_HTTP.functions.bif.zeek 14 14

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`any`

   Skips the data of the HTTP entity.
   

   :param c: The HTTP connection.
   

   :param is_orig: If true, the client data is skipped, and the server data otherwise.
   
   .. zeek:see:: skip_smtp_data

.. zeek:id:: unescape_URI
   :source-code: base/bif/plugins/Zeek_HTTP.functions.bif.zeek 30 30

   :Type: :zeek:type:`function` (URI: :zeek:type:`string`) : :zeek:type:`string`

   Unescapes all characters in a URI (decode every ``%xx`` group).
   

   :param URI: The URI to unescape.
   

   :returns: The unescaped URI with all ``%xx`` groups decoded.
   
   .. note::
   
        Unescaping reserved characters may cause loss of information.
        :rfc:`2396`: A URI is always in an "escaped" form, since escaping or
        unescaping a completed URI might change its semantics.  Normally, the
        only time escape encodings can safely be made is when the URI is
        being created from its component parts.


