:tocdepth: 3

base/protocols/syslog/consts.bro
================================
.. bro:namespace:: Syslog

Constants definitions for syslog.

:Namespace: Syslog

Summary
~~~~~~~
Constants
#########
===================================================================================================================== ======================================================================
:bro:id:`Syslog::facility_codes`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` Mapping between the constants and string values for syslog facilities.
:bro:id:`Syslog::severity_codes`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` Mapping between the constants and string values for syslog severities.
===================================================================================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. bro:id:: Syslog::facility_codes

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "MAIL",
         [9] = "CRON",
         [17] = "LOCAL1",
         [6] = "LPR",
         [11] = "FTP",
         [14] = "ALERT",
         [4] = "AUTH",
         [22] = "LOCAL6",
         [1] = "USER",
         [8] = "UUCP",
         [7] = "NEWS",
         [15] = "CLOCK",
         [23] = "LOCAL7",
         [5] = "SYSLOG",
         [19] = "LOCAL3",
         [10] = "AUTHPRIV",
         [0] = "KERN",
         [3] = "DAEMON",
         [12] = "NTP",
         [13] = "AUDIT",
         [18] = "LOCAL2",
         [21] = "LOCAL5",
         [16] = "LOCAL0",
         [20] = "LOCAL4"
      }

   Mapping between the constants and string values for syslog facilities.

.. bro:id:: Syslog::severity_codes

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "CRIT",
         [6] = "INFO",
         [4] = "WARNING",
         [1] = "ALERT",
         [7] = "DEBUG",
         [5] = "NOTICE",
         [0] = "EMERG",
         [3] = "ERR"
      }

   Mapping between the constants and string values for syslog severities.


