:tocdepth: 3

policy/frameworks/software/version-changes.zeek
===============================================
.. zeek:namespace:: Software

Provides the possibility to define software names that are interesting to
watch for changes.  A notice is generated if software versions change on a
host.

:Namespace: Software
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`

Summary
~~~~~~~
Runtime Options
###############
====================================================================================== ====================================================================
:zeek:id:`Software::interesting_version_changes`: :zeek:type:`set` :zeek:attr:`&redef` Some software is more interesting when the version changes and this
                                                                                       is a set of all software that should raise a notice when a different
                                                                                       version is seen on a host.
====================================================================================== ====================================================================

Redefinitions
#############
============================================ ======================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`Software::Software_Version_Change`:
                                               For certain software, a version changing may matter.
============================================ ======================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Software::interesting_version_changes
   :source-code: policy/frameworks/software/version-changes.zeek 22 22

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Some software is more interesting when the version changes and this
   is a set of all software that should raise a notice when a different
   version is seen on a host.


