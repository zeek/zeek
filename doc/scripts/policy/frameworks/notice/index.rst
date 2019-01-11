:orphan:

Package: policy/frameworks/notice
=================================


:doc:`/scripts/policy/frameworks/notice/__load__.bro`


:doc:`/scripts/policy/frameworks/notice/extend-email/hostnames.bro`

   Loading this script extends the :bro:enum:`Notice::ACTION_EMAIL` action
   by appending to the email the hostnames associated with
   :bro:type:`Notice::Info`'s *src* and *dst* fields as determined by a
   DNS lookup.

