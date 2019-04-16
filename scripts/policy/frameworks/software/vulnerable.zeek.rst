:tocdepth: 3

policy/frameworks/software/vulnerable.zeek
==========================================
.. bro:namespace:: Software

Provides a variable to define vulnerable versions of software and if
a version of that software is as old or older than the defined version a
notice will be generated.

:Namespace: Software
:Imports: :doc:`base/frameworks/control </scripts/base/frameworks/control/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================================ =============================================================
:bro:id:`Software::vulnerable_versions_update_endpoint`: :bro:type:`string` :bro:attr:`&redef`   The DNS zone where runtime vulnerable software updates will
                                                                                                 be loaded from.
:bro:id:`Software::vulnerable_versions_update_interval`: :bro:type:`interval` :bro:attr:`&redef` The interval at which vulnerable versions should grab updates
                                                                                                 over DNS.
================================================================================================ =============================================================

Redefinable Options
###################
============================================================================= ===============================================================
:bro:id:`Software::vulnerable_versions`: :bro:type:`table` :bro:attr:`&redef` This is a table of software versions indexed by the name of the
                                                                              software and a set of version ranges that are declared to be
                                                                              vulnerable for that software.
============================================================================= ===============================================================

Types
#####
================================================================ =
:bro:type:`Software::VulnerableVersionRange`: :bro:type:`record` 
================================================================ =

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Software::vulnerable_versions_update_endpoint

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   The DNS zone where runtime vulnerable software updates will
   be loaded from.

.. bro:id:: Software::vulnerable_versions_update_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 hr``

   The interval at which vulnerable versions should grab updates
   over DNS.

Redefinable Options
###################
.. bro:id:: Software::vulnerable_versions

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`set` [:bro:type:`Software::VulnerableVersionRange`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   This is a table of software versions indexed by the name of the
   software and a set of version ranges that are declared to be
   vulnerable for that software.

Types
#####
.. bro:type:: Software::VulnerableVersionRange

   :Type: :bro:type:`record`

      min: :bro:type:`Software::Version` :bro:attr:`&optional`
         The minimal version of a vulnerable version range.  This
         field can be undefined if all previous versions of a piece
         of software are vulnerable.

      max: :bro:type:`Software::Version`
         The maximum vulnerable version.  This field is deliberately
         not optional because a maximum vulnerable version must
         always be defined.  This assumption may become incorrect
         if all future versions of some software are to be considered
         vulnerable. :)



