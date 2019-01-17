:tocdepth: 3

base/protocols/irc/files.bro
============================
.. bro:namespace:: IRC


:Namespace: IRC
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/irc/dcc-send.bro </scripts/base/protocols/irc/dcc-send.bro>`, :doc:`base/utils/conn-ids.bro </scripts/base/utils/conn-ids.bro>`

Summary
~~~~~~~
Redefinitions
#############
========================================================== =
:bro:type:`IRC::Info`: :bro:type:`record`                  
:bro:type:`fa_file`: :bro:type:`record` :bro:attr:`&redef` 
========================================================== =

Functions
#########
==================================================== =====================================
:bro:id:`IRC::get_file_handle`: :bro:type:`function` Default file handle provider for IRC.
==================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: IRC::get_file_handle

   :Type: :bro:type:`function` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`) : :bro:type:`string`

   Default file handle provider for IRC.


