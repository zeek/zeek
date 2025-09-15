:tocdepth: 3

base/frameworks/notice/actions/pp-alarms.zeek
=============================================
.. zeek:namespace:: Notice

Notice extension that mails out a pretty-printed version of notice_alarm.log
in regular intervals, formatted for better human readability. If activated,
that replaces the default summary mail having the raw log output.

:Namespace: Notice
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/notice/main.zeek </scripts/base/frameworks/notice/main.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
==================================================================================== ==============================================
:zeek:id:`Notice::mail_dest_pretty_printed`: :zeek:type:`string` :zeek:attr:`&redef` Address to send the pretty-printed reports to.
:zeek:id:`Notice::pretty_print_alarms`: :zeek:type:`bool` :zeek:attr:`&redef`        Activate pretty-printed alarm summaries.
==================================================================================== ==============================================

State Variables
###############
=============================================================================== ==================================================================
:zeek:id:`Notice::flag_nets`: :zeek:type:`set` :zeek:attr:`&redef`              If an address from one of these networks is reported, we mark
                                                                                the entry with an additional quote symbol (i.e., ">").
:zeek:id:`Notice::force_email_summaries`: :zeek:type:`bool` :zeek:attr:`&redef` Force generating mail file, even if reading from traces or no mail
                                                                                destination is defined.
=============================================================================== ==================================================================

Functions
#########
================================================================================ =====================================
:zeek:id:`Notice::pretty_print_alarm`: :zeek:type:`function` :zeek:attr:`&redef` Function that renders a single alarm.
================================================================================ =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Notice::mail_dest_pretty_printed
   :source-code: base/frameworks/notice/actions/pp-alarms.zeek 18 18

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Address to send the pretty-printed reports to. Default if not set is
   :zeek:id:`Notice::mail_dest`.
   
   Note that this is overridden by the ZeekControl MailAlarmsTo option.

.. zeek:id:: Notice::pretty_print_alarms
   :source-code: base/frameworks/notice/actions/pp-alarms.zeek 12 12

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Activate pretty-printed alarm summaries.

State Variables
###############
.. zeek:id:: Notice::flag_nets
   :source-code: base/frameworks/notice/actions/pp-alarms.zeek 22 22

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   If an address from one of these networks is reported, we mark
   the entry with an additional quote symbol (i.e., ">"). Many MUAs
   then highlight such lines differently.

.. zeek:id:: Notice::force_email_summaries
   :source-code: base/frameworks/notice/actions/pp-alarms.zeek 29 29

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Force generating mail file, even if reading from traces or no mail
   destination is defined. This is mainly for testing.

Functions
#########
.. zeek:id:: Notice::pretty_print_alarm
   :source-code: base/frameworks/notice/actions/pp-alarms.zeek 152 254

   :Type: :zeek:type:`function` (out: :zeek:type:`file`, n: :zeek:type:`Notice::Info`) : :zeek:type:`void`
   :Attributes: :zeek:attr:`&redef`

   Function that renders a single alarm. Can be overridden.


