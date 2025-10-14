:tocdepth: 3

policy/frameworks/software/vulnerable.zeek
==========================================
.. zeek:namespace:: Software

Provides a variable to define vulnerable versions of software and if
a version of that software is as old or older than the defined version a
notice will be generated.

:Namespace: Software
:Imports: :doc:`base/frameworks/control </scripts/base/frameworks/control/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`

Summary
~~~~~~~
Runtime Options
###############
=================================================================================================== =============================================================
:zeek:id:`Software::vulnerable_versions_update_endpoint`: :zeek:type:`string` :zeek:attr:`&redef`   The DNS zone where runtime vulnerable software updates will
                                                                                                    be loaded from.
:zeek:id:`Software::vulnerable_versions_update_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The interval at which vulnerable versions should grab updates
                                                                                                    over DNS.
=================================================================================================== =============================================================

Redefinable Options
###################
================================================================================ ===============================================================
:zeek:id:`Software::vulnerable_versions`: :zeek:type:`table` :zeek:attr:`&redef` This is a table of software versions indexed by the name of the
                                                                                 software and a set of version ranges that are declared to be
                                                                                 vulnerable for that software.
================================================================================ ===============================================================

Types
#####
================================================================== =
:zeek:type:`Software::VulnerableVersionRange`: :zeek:type:`record` 
================================================================== =

Redefinitions
#############
============================================ ===============================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`Software::Vulnerable_Version`:
                                               Indicates that a vulnerable version of software was detected.
============================================ ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Software::vulnerable_versions_update_endpoint
   :source-code: policy/frameworks/software/vulnerable.zeek 32 32

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The DNS zone where runtime vulnerable software updates will
   be loaded from.

.. zeek:id:: Software::vulnerable_versions_update_interval
   :source-code: policy/frameworks/software/vulnerable.zeek 36 36

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 hr``

   The interval at which vulnerable versions should grab updates
   over DNS.

Redefinable Options
###################
.. zeek:id:: Software::vulnerable_versions
   :source-code: policy/frameworks/software/vulnerable.zeek 41 41

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`set` [:zeek:type:`Software::VulnerableVersionRange`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   This is a table of software versions indexed by the name of the
   software and a set of version ranges that are declared to be
   vulnerable for that software.

Types
#####
.. zeek:type:: Software::VulnerableVersionRange
   :source-code: policy/frameworks/software/vulnerable.zeek 17 28

   :Type: :zeek:type:`record`

      min: :zeek:type:`Software::Version` :zeek:attr:`&optional`
         The minimal version of a vulnerable version range.  This
         field can be undefined if all previous versions of a piece
         of software are vulnerable.

      max: :zeek:type:`Software::Version`
         The maximum vulnerable version.  This field is deliberately
         not optional because a maximum vulnerable version must
         always be defined.  This assumption may become incorrect
         if all future versions of some software are to be considered
         vulnerable. :)



