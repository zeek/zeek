:tocdepth: 3

base/protocols/irc/files.zeek
=============================
.. zeek:namespace:: IRC


:Namespace: IRC
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/irc/dcc-send.zeek </scripts/base/protocols/irc/dcc-send.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================================= ====================================================================
:zeek:type:`IRC::Info`: :zeek:type:`record`                   
                                                              
                                                              :New Fields: :zeek:type:`IRC::Info`
                                                              
                                                                fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                  File unique ID.
:zeek:type:`fa_file`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                              
                                                              :New Fields: :zeek:type:`fa_file`
                                                              
                                                                irc: :zeek:type:`IRC::Info` :zeek:attr:`&optional`
============================================================= ====================================================================

Functions
#########
====================================================== =====================================
:zeek:id:`IRC::get_file_handle`: :zeek:type:`function` Default file handle provider for IRC.
====================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: IRC::get_file_handle
   :source-code: base/protocols/irc/files.zeek 21 24

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for IRC.


