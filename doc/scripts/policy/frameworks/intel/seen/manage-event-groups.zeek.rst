:tocdepth: 3

policy/frameworks/intel/seen/manage-event-groups.zeek
=====================================================
.. zeek:namespace:: Intel


:Namespace: Intel
:Imports: :doc:`base/frameworks/reporter </scripts/base/frameworks/reporter/index>`, :doc:`policy/frameworks/intel/seen </scripts/policy/frameworks/intel/seen/index>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================================= ============================================================
:zeek:id:`Intel::manage_seen_event_groups`: :zeek:type:`bool` :zeek:attr:`&redef` Whether Intel event groups for the seen scripts are managed.
================================================================================= ============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Intel::manage_seen_event_groups
   :source-code: policy/frameworks/intel/seen/manage-event-groups.zeek 21 21

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether Intel event groups for the seen scripts are managed.
   
   When loading this script, by default, all :zeek:see:`Intel::Type`
   event groups are disabled at startup and only enabled when indicators
   of corresponding types are loaded into the Intel framework's store.
   This allows to load the ``frameworks/intel/seen`` scripts without
   incurring event handling overhead when no Intel indicators are loaded.
   
   One caveat is that the :zeek:see:`Intel::seen_policy` hook will not
   be invoked for indicator types that are not at all in the Intel
   framework's store. If you rely on :zeek:see:`Intel::seen_policy` to
   find unmatched indicators, do not not load this script, set this
   variable to ``F``, or insert dummy values of the types using
   :zeek:see:`Intel::insert`.


