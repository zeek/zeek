:tocdepth: 3

base/bif/plugins/Bro_HTTP.functions.bif.zeek
============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
===================================================== ===============================================================
:bro:id:`skip_http_entity_data`: :bro:type:`function` Skips the data of the HTTP entity.
:bro:id:`unescape_URI`: :bro:type:`function`          Unescapes all characters in a URI (decode every ``%xx`` group).
===================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: skip_http_entity_data

   :Type: :bro:type:`function` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`) : :bro:type:`any`

   Skips the data of the HTTP entity.
   

   :c: The HTTP connection.
   

   :is_orig: If true, the client data is skipped, and the server data otherwise.
   
   .. bro:see:: skip_smtp_data

.. bro:id:: unescape_URI

   :Type: :bro:type:`function` (URI: :bro:type:`string`) : :bro:type:`string`

   Unescapes all characters in a URI (decode every ``%xx`` group).
   

   :URI: The URI to unescape.
   

   :returns: The unescaped URI with all ``%xx`` groups decoded.
   
   .. note::
   
        Unescaping reserved characters may cause loss of information.
        :rfc:`2396`: A URI is always in an "escaped" form, since escaping or
        unescaping a completed URI might change its semantics.  Normally, the
        only time escape encodings can safely be made is when the URI is
        being created from its component parts.


