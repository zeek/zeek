:orphan:

Package: base/frameworks/notice
===============================

The notice framework enables Zeek to "notice" things which are odd or
potentially bad, leaving it to the local configuration to define which
of them are actionable.  This decoupling of detection and reporting allows
Zeek to be customized to the different needs that sites have.

:doc:`/scripts/base/frameworks/notice/__load__.zeek`


:doc:`/scripts/base/frameworks/notice/main.zeek`

   This is the notice framework which enables Zeek to "notice" things which
   are odd or potentially bad.  Decisions of the meaning of various notices
   need to be done per site because Zeek does not ship with assumptions about
   what is bad activity for sites.  More extensive documentation about using
   the notice framework can be found in :doc:`/frameworks/notice`.

:doc:`/scripts/base/frameworks/notice/weird.zeek`

   This script provides a default set of actions to take for "weird activity"
   events generated from Zeek's event engine.  Weird activity is defined as
   unusual or exceptional activity that can indicate malformed connections,
   traffic that doesn't conform to a particular protocol, malfunctioning
   or misconfigured hardware, or even an attacker attempting to avoid/confuse
   a sensor.  Without context, it's hard to judge whether a particular
   category of weird activity is interesting, but this script provides
   a starting point for the user.

:doc:`/scripts/base/frameworks/notice/actions/email_admin.zeek`

   Adds a new notice action type which can be used to email notices
   to the administrators of a particular address space as set by
   :zeek:id:`Site::local_admins` if the notice contains a source
   or destination address that lies within their space.

:doc:`/scripts/base/frameworks/notice/actions/page.zeek`

   Allows configuration of a pager email address to which notices can be sent.

:doc:`/scripts/base/frameworks/notice/actions/add-geodata.zeek`

   This script adds geographic location data to notices for the "remote"
   host in a connection.  It does make the assumption that one of the
   addresses in a connection is "local" and one is "remote" which is
   probably a safe assumption to make in most cases.  If both addresses
   are remote, it will use the $src address.

:doc:`/scripts/base/frameworks/notice/actions/pp-alarms.zeek`

   Notice extension that mails out a pretty-printed version of notice_alarm.log
   in regular intervals, formatted for better human readability. If activated,
   that replaces the default summary mail having the raw log output.

