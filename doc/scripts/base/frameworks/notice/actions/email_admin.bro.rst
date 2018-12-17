:tocdepth: 3

base/frameworks/notice/actions/email_admin.bro
==============================================
.. bro:namespace:: Notice

Adds a new notice action type which can be used to email notices
to the administrators of a particular address space as set by
:bro:id:`Site::local_admins` if the notice contains a source
or destination address that lies within their space.

:Namespace: Notice
:Imports: :doc:`base/frameworks/notice/main.bro </scripts/base/frameworks/notice/main.bro>`, :doc:`base/utils/site.bro </scripts/base/utils/site.bro>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =
:bro:type:`Notice::Action`: :bro:type:`enum` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~

