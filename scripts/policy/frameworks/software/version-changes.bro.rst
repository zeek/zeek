:tocdepth: 3

policy/frameworks/software/version-changes.bro
==============================================
.. bro:namespace:: Software

Provides the possibility to define software names that are interesting to
watch for changes.  A notice is generated if software versions change on a
host.

:Namespace: Software
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`

Summary
~~~~~~~
Runtime Options
###############
=================================================================================== ====================================================================
:bro:id:`Software::interesting_version_changes`: :bro:type:`set` :bro:attr:`&redef` Some software is more interesting when the version changes and this
                                                                                    is a set of all software that should raise a notice when a different
                                                                                    version is seen on a host.
=================================================================================== ====================================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Software::interesting_version_changes

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Some software is more interesting when the version changes and this
   is a set of all software that should raise a notice when a different
   version is seen on a host.


