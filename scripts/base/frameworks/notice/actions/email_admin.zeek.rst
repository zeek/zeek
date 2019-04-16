:tocdepth: 3

base/frameworks/notice/actions/email_admin.zeek
===============================================
.. bro:namespace:: Notice

Adds a new notice action type which can be used to email notices
to the administrators of a particular address space as set by
:bro:id:`Site::local_admins` if the notice contains a source
or destination address that lies within their space.

:Namespace: Notice
:Imports: :doc:`base/frameworks/notice/main.zeek </scripts/base/frameworks/notice/main.zeek>`, :doc:`base/utils/site.zeek </scripts/base/utils/site.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =
:bro:type:`Notice::Action`: :bro:type:`enum` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~

