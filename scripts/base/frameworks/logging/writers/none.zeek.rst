:tocdepth: 3

base/frameworks/logging/writers/none.zeek
=========================================
.. bro:namespace:: LogNone

Interface for the None log writer. This writer is mainly for debugging.

:Namespace: LogNone

Summary
~~~~~~~
Redefinable Options
###################
============================================================= ============================================================
:bro:id:`LogNone::debug`: :bro:type:`bool` :bro:attr:`&redef` If true, output debugging output that can be useful for unit
                                                              testing the logging framework.
============================================================= ============================================================

Redefinitions
#############
==================================================================================== =
:bro:id:`Log::default_rotation_postprocessors`: :bro:type:`table` :bro:attr:`&redef` 
==================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: LogNone::debug

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, output debugging output that can be useful for unit
   testing the logging framework.


