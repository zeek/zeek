:tocdepth: 3

base/frameworks/notice/actions/page.bro
=======================================
.. bro:namespace:: Notice

Allows configuration of a pager email address to which notices can be sent.

:Namespace: Notice
:Imports: :doc:`base/frameworks/notice/main.bro </scripts/base/frameworks/notice/main.bro>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================= ======================================================================
:bro:id:`Notice::mail_page_dest`: :bro:type:`string` :bro:attr:`&redef` Email address to send notices with the :bro:enum:`Notice::ACTION_PAGE`
                                                                        action.
======================================================================= ======================================================================

Redefinitions
#############
============================================ =
:bro:type:`Notice::Action`: :bro:type:`enum` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Notice::mail_page_dest

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Email address to send notices with the :bro:enum:`Notice::ACTION_PAGE`
   action.


