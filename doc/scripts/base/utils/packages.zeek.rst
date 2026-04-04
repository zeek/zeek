:tocdepth: 3

base/utils/packages.zeek
========================

Rudimentary functions for helping with Zeek packages.


Summary
~~~~~~~
Functions
#########
========================================== ==================================================
:zeek:id:`can_load`: :zeek:type:`function` Checks whether @load of a given package name could
                                           be successful.
========================================== ==================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: can_load
   :source-code: base/utils/packages.zeek 13 16

   :Type: :zeek:type:`function` (p: :zeek:type:`string`) : :zeek:type:`bool`

   Checks whether @load of a given package name could
   be successful.

   This tests for the existence of corresponding script files
   in ZEEKPATH. It does not attempt to parse and validate
   any actual Zeek script code.


   :param path: The filename, package or path to test.


   :returns: T if the given filename, package or path may load.


