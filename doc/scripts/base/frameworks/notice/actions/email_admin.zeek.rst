:tocdepth: 3

base/frameworks/notice/actions/email_admin.zeek
===============================================
.. zeek:namespace:: Notice

Adds a new notice action type which can be used to email notices
to the administrators of a particular address space as set by
:zeek:id:`Site::local_admins` if the notice contains a source
or destination address that lies within their space.

:Namespace: Notice
:Imports: :doc:`base/frameworks/notice/main.zeek </scripts/base/frameworks/notice/main.zeek>`, :doc:`base/utils/site.zeek </scripts/base/utils/site.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================== ==============================================================
:zeek:type:`Notice::Action`: :zeek:type:`enum` 
                                               
                                               * :zeek:enum:`Notice::ACTION_EMAIL_ADMIN`:
                                                 Indicate that the generated email should be addressed to the
                                                 appropriate email addresses as found by the
                                                 :zeek:id:`Site::get_emails` function based on the relevant
                                                 address or addresses indicated in the notice.
============================================== ==============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

