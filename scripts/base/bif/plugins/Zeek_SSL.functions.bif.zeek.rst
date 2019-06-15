:tocdepth: 3

base/bif/plugins/Zeek_SSL.functions.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
===================================================== ==============================================================================
:zeek:id:`set_ssl_established`: :zeek:type:`function` Sets if the SSL analyzer should consider the connection established (handshake
                                                      finished succesfully).
===================================================== ==============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: set_ssl_established

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`) : :zeek:type:`any`

   Sets if the SSL analyzer should consider the connection established (handshake
   finished succesfully).
   

   :c: The SSL connection.


