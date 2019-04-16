:tocdepth: 3

base/bif/plugins/Bro_SSL.functions.bif.zeek
===========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
=================================================== ==============================================================================
:bro:id:`set_ssl_established`: :bro:type:`function` Sets if the SSL analyzer should consider the connection established (handshake
                                                    finished succesfully).
=================================================== ==============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: set_ssl_established

   :Type: :bro:type:`function` (c: :bro:type:`connection`) : :bro:type:`any`

   Sets if the SSL analyzer should consider the connection established (handshake
   finished succesfully).
   

   :c: The SSL connection.


