:tocdepth: 3

base/frameworks/logging/writers/none.zeek
=========================================
.. zeek:namespace:: LogNone

Interface for the None log writer. This writer is mainly for debugging.

:Namespace: LogNone

Summary
~~~~~~~
Redefinable Options
###################
================================================================ ============================================================
:zeek:id:`LogNone::debug`: :zeek:type:`bool` :zeek:attr:`&redef` If true, output debugging output that can be useful for unit
                                                                 testing the logging framework.
================================================================ ============================================================

Redefinitions
#############
======================================================================================= =
:zeek:id:`Log::default_rotation_postprocessors`: :zeek:type:`table` :zeek:attr:`&redef` 
======================================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: LogNone::debug
   :source-code: base/frameworks/logging/writers/none.zeek 8 8

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, output debugging output that can be useful for unit
   testing the logging framework.


