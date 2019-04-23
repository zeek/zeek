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
============================================================= =
:zeek:type:`IRC::Info`: :zeek:type:`record`                   
:zeek:type:`fa_file`: :zeek:type:`record` :zeek:attr:`&redef` 
============================================================= =

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

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for IRC.


