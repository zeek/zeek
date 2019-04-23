:orphan:

Package: policy/frameworks/notice
=================================


:doc:`/scripts/policy/frameworks/notice/__load__.zeek`


:doc:`/scripts/policy/frameworks/notice/extend-email/hostnames.zeek`

   Loading this script extends the :zeek:enum:`Notice::ACTION_EMAIL` action
   by appending to the email the hostnames associated with
   :zeek:type:`Notice::Info`'s *src* and *dst* fields as determined by a
   DNS lookup.

