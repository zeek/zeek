:tocdepth: 3

base/frameworks/notice/actions/page.zeek
========================================
.. zeek:namespace:: Notice

Allows configuration of a pager email address to which notices can be sent.

:Namespace: Notice
:Imports: :doc:`base/frameworks/notice/main.zeek </scripts/base/frameworks/notice/main.zeek>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================== =======================================================================
:zeek:id:`Notice::mail_page_dest`: :zeek:type:`string` :zeek:attr:`&redef` Email address to send notices with the :zeek:enum:`Notice::ACTION_PAGE`
                                                                           action.
========================================================================== =======================================================================

Redefinitions
#############
============================================== =============================================================
:zeek:type:`Notice::Action`: :zeek:type:`enum` 
                                               
                                               * :zeek:enum:`Notice::ACTION_PAGE`:
                                                 Indicates that the notice should be sent to the pager email
                                                 address configured in the :zeek:id:`Notice::mail_page_dest`
                                                 variable.
============================================== =============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Notice::mail_page_dest
   :source-code: base/frameworks/notice/actions/page.zeek 17 17

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Email address to send notices with the :zeek:enum:`Notice::ACTION_PAGE`
   action.


