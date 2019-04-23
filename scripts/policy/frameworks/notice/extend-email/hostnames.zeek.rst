:tocdepth: 3

policy/frameworks/notice/extend-email/hostnames.zeek
====================================================
.. zeek:namespace:: Notice

Loading this script extends the :zeek:enum:`Notice::ACTION_EMAIL` action
by appending to the email the hostnames associated with
:zeek:type:`Notice::Info`'s *src* and *dst* fields as determined by a
DNS lookup.

:Namespace: Notice
:Imports: :doc:`base/frameworks/notice/main.zeek </scripts/base/frameworks/notice/main.zeek>`

Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

