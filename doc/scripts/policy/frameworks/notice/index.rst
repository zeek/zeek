:orphan:

Package: policy/frameworks/notice
=================================


:doc:`/scripts/policy/frameworks/notice/__load__.zeek`


:doc:`/scripts/policy/frameworks/notice/extend-email/hostnames.zeek`

   Loading this script extends the :zeek:enum:`Notice::ACTION_EMAIL` action
   by appending to the email the hostnames associated with
   :zeek:type:`Notice::Info`'s *src* and *dst* fields as determined by a
   DNS lookup.

:doc:`/scripts/policy/frameworks/notice/actions/drop.zeek`

   This script extends the built in notice code to implement the IP address
   dropping functionality.

:doc:`/scripts/policy/frameworks/notice/community-id.zeek`


