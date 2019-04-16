:tocdepth: 3

policy/misc/loaded-scripts.zeek
===============================
.. bro:namespace:: LoadedScripts

Log the loaded scripts.

:Namespace: LoadedScripts
:Imports: :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`

Summary
~~~~~~~
Types
#####
=================================================== =
:bro:type:`LoadedScripts::Info`: :bro:type:`record` 
=================================================== =

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: LoadedScripts::Info

   :Type: :bro:type:`record`

      name: :bro:type:`string` :bro:attr:`&log`
         Name of the script loaded potentially with spaces included
         before the file name to indicate load depth.  The convention
         is two spaces per level of depth.



