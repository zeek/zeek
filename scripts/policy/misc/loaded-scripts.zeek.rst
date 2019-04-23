:tocdepth: 3

policy/misc/loaded-scripts.zeek
===============================
.. zeek:namespace:: LoadedScripts

Log the loaded scripts.

:Namespace: LoadedScripts
:Imports: :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`

Summary
~~~~~~~
Types
#####
===================================================== =
:zeek:type:`LoadedScripts::Info`: :zeek:type:`record` 
===================================================== =

Redefinitions
#############
======================================= =
:zeek:type:`Log::ID`: :zeek:type:`enum` 
======================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: LoadedScripts::Info

   :Type: :zeek:type:`record`

      name: :zeek:type:`string` :zeek:attr:`&log`
         Name of the script loaded potentially with spaces included
         before the file name to indicate load depth.  The convention
         is two spaces per level of depth.



