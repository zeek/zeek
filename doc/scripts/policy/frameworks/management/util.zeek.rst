:tocdepth: 3

policy/frameworks/management/util.zeek
======================================
.. zeek:namespace:: Management::Util

Utility functions for the Management framework, available to agent
and controller.

:Namespace: Management::Util

Summary
~~~~~~~
Functions
#########
================================================================= ============================================================
:zeek:id:`Management::Util::set_to_vector`: :zeek:type:`function` Renders a set of strings to an alphabetically sorted vector.
================================================================= ============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Management::Util::set_to_vector
   :source-code: policy/frameworks/management/util.zeek 15 25

   :Type: :zeek:type:`function` (ss: :zeek:type:`set` [:zeek:type:`string`]) : :zeek:type:`vector` of :zeek:type:`string`

   Renders a set of strings to an alphabetically sorted vector.


   :param ss: the string set to convert.


   :returns: the vector of all strings in ss.


