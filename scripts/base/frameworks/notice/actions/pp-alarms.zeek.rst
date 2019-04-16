:tocdepth: 3

base/frameworks/notice/actions/pp-alarms.zeek
=============================================
.. bro:namespace:: Notice

Notice extension that mails out a pretty-printed version of alarm.log
in regular intervals, formatted for better human readability. If activated,
that replaces the default summary mail having the raw log output.

:Namespace: Notice
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/notice/main.zeek </scripts/base/frameworks/notice/main.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================================= ==============================================
:bro:id:`Notice::mail_dest_pretty_printed`: :bro:type:`string` :bro:attr:`&redef` Address to send the pretty-printed reports to.
:bro:id:`Notice::pretty_print_alarms`: :bro:type:`bool` :bro:attr:`&redef`        Activate pretty-printed alarm summaries.
================================================================================= ==============================================

State Variables
###############
============================================================================ ==================================================================
:bro:id:`Notice::flag_nets`: :bro:type:`set` :bro:attr:`&redef`              If an address from one of these networks is reported, we mark
                                                                             the entry with an additional quote symbol (i.e., ">").
:bro:id:`Notice::force_email_summaries`: :bro:type:`bool` :bro:attr:`&redef` Force generating mail file, even if reading from traces or no mail
                                                                             destination is defined.
============================================================================ ==================================================================

Functions
#########
============================================================================= =====================================
:bro:id:`Notice::pretty_print_alarm`: :bro:type:`function` :bro:attr:`&redef` Function that renders a single alarm.
============================================================================= =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Notice::mail_dest_pretty_printed

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Address to send the pretty-printed reports to. Default if not set is
   :bro:id:`Notice::mail_dest`.
   
   Note that this is overridden by the BroControl MailAlarmsTo option.

.. bro:id:: Notice::pretty_print_alarms

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Activate pretty-printed alarm summaries.

State Variables
###############
.. bro:id:: Notice::flag_nets

   :Type: :bro:type:`set` [:bro:type:`subnet`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   If an address from one of these networks is reported, we mark
   the entry with an additional quote symbol (i.e., ">"). Many MUAs
   then highlight such lines differently.

.. bro:id:: Notice::force_email_summaries

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Force generating mail file, even if reading from traces or no mail
   destination is defined. This is mainly for testing.

Functions
#########
.. bro:id:: Notice::pretty_print_alarm

   :Type: :bro:type:`function` (out: :bro:type:`file`, n: :bro:type:`Notice::Info`) : :bro:type:`void`
   :Attributes: :bro:attr:`&redef`

   Function that renders a single alarm. Can be overridden.


