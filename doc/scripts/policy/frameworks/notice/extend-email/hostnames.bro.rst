:tocdepth: 3

policy/frameworks/notice/extend-email/hostnames.bro
===================================================
.. bro:namespace:: Notice

Loading this script extends the :bro:enum:`Notice::ACTION_EMAIL` action
by appending to the email the hostnames associated with
:bro:type:`Notice::Info`'s *src* and *dst* fields as determined by a
DNS lookup.

:Namespace: Notice
:Imports: :doc:`base/frameworks/notice/main.bro </scripts/base/frameworks/notice/main.bro>`

Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

