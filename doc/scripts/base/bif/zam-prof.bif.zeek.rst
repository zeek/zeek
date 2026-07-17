:tocdepth: 3

base/bif/zam-prof.bif.zeek
==========================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: ZAM::Prof

Functions to enable script-level control & querying of ZAM profiling.

:Namespaces: GLOBAL, ZAM::Prof

Summary
~~~~~~~
Functions
#########
========================================================================= ==========================================================================
:zeek:id:`ZAM::Prof::estimated_profiling_overhead`: :zeek:type:`function` Returns an estimate of the timing overhead of each CPU/memory measurement.
:zeek:id:`ZAM::Prof::get_module_profile`: :zeek:type:`function`           Returns the profile for the given module so far.
:zeek:id:`ZAM::Prof::set_module_profiling`: :zeek:type:`function`         Activates/deactivates CPU+memory profiling for all ZAM-compiled bodies
                                                                          that include the given module.
========================================================================= ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: ZAM::Prof::estimated_profiling_overhead
   :source-code: base/bif/zam-prof.bif.zeek 66 66

   :Type: :zeek:type:`function` () : :zeek:type:`interval`

   Returns an estimate of the timing overhead of each CPU/memory measurement.
   Can be used to attempt to remove bias in assessing those measurements.


   :returns: The estimate of the total overhead, as a non-negative interval.

   .. note::

      This value is fixed per Zeek run. Repeated calls to it from within
      that run will return the same value.

   .. zeek:see:: ZAM::Prof::set_module_profiling ZAM::Prof::get_module_profile

.. zeek:id:: ZAM::Prof::get_module_profile
   :source-code: base/bif/zam-prof.bif.zeek 51 51

   :Type: :zeek:type:`function` (mod: :zeek:type:`string`) : :zeek:type:`ZAM::Prof::Profile`

   Returns the profile for the given module so far.

   .. zeek:see:: ZAM::Prof::set_module_profiling ZAM::Prof::estimated_profiling_overhead

.. zeek:id:: ZAM::Prof::set_module_profiling
   :source-code: base/bif/zam-prof.bif.zeek 45 45

   :Type: :zeek:type:`function` (mod: :zeek:type:`string`, active: :zeek:type:`bool`) : :zeek:type:`count`

   Activates/deactivates CPU+memory profiling for all ZAM-compiled bodies
   that include the given module.


   :param mod: the name of the module

   :param active: if true, active, otherwise deactivate


   :returns: How many bodies were set to the given profiling.

   .. note::

      Overrides any previously set sampling for the module.

   .. note::

      The return value will often indicate fewer bodies than present in
      the module due to inlining. On the flip side, it can indicate more
      bodies than present in the module due to ZAM generates bodies for
      both standalone and "coalesced" versions of event handlers.

   .. note::

      Due to event handler coalescence (enabled by default), some ZAM-compiled
      bodies will correspond to multiple modules. For these bodies, sampling
      activation follows the most recent call for any of those modules.

   .. note::

      A return value of 0 means the module name doesn't correspond to
      any compiled bodies. This will always be the case if Zeek is not
      running with some form of -O ZAM enabled.

   .. zeek:see:: ZAM::Prof::get_module_profile ZAM::Prof::estimated_profiling_overhead


