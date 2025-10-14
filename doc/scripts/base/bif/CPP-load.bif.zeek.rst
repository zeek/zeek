:tocdepth: 3

base/bif/CPP-load.bif.zeek
==========================
.. zeek:namespace:: GLOBAL

Definitions of built-in functions related to loading compiled-to-C++
scripts.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
========================================== ====================================================================
:zeek:id:`load_CPP`: :zeek:type:`function` Activates the compile-to-C++ scripts associated with the given hash.
========================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: load_CPP
   :source-code: base/bif/CPP-load.bif.zeek 16 16

   :Type: :zeek:type:`function` (h: :zeek:type:`count`) : :zeek:type:`bool`

   Activates the compile-to-C++ scripts associated with the given hash.
   

   :param h: Hash of the set of C++ scripts.
   

   :returns: True if it was present and loaded, false if not.
   


