:tocdepth: 3

base/protocols/syslog/consts.zeek
=================================
.. zeek:namespace:: Syslog

Constants definitions for syslog.

:Namespace: Syslog

Summary
~~~~~~~
Constants
#########
=================================================================================================== ======================================================================
:zeek:id:`Syslog::facility_codes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` Mapping between the constants and string values for syslog facilities.
:zeek:id:`Syslog::severity_codes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` Mapping between the constants and string values for syslog severities.
=================================================================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: Syslog::facility_codes
   :source-code: base/protocols/syslog/consts.zeek 7 7

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [19] = "LOCAL3",
            [2] = "MAIL",
            [20] = "LOCAL4",
            [14] = "ALERT",
            [15] = "CLOCK",
            [6] = "LPR",
            [16] = "LOCAL0",
            [8] = "UUCP",
            [23] = "LOCAL7",
            [9] = "CRON",
            [1] = "USER",
            [11] = "FTP",
            [999] = "UNSPECIFIED",
            [5] = "SYSLOG",
            [7] = "NEWS",
            [21] = "LOCAL5",
            [10] = "AUTHPRIV",
            [22] = "LOCAL6",
            [4] = "AUTH",
            [12] = "NTP",
            [13] = "AUDIT",
            [18] = "LOCAL2",
            [3] = "DAEMON",
            [17] = "LOCAL1",
            [0] = "KERN"
         }


   Mapping between the constants and string values for syslog facilities.

.. zeek:id:: Syslog::severity_codes
   :source-code: base/protocols/syslog/consts.zeek 36 36

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "CRIT",
            [999] = "UNSPECIFIED",
            [5] = "NOTICE",
            [7] = "DEBUG",
            [3] = "ERR",
            [0] = "EMERG",
            [6] = "INFO",
            [4] = "WARNING",
            [1] = "ALERT"
         }


   Mapping between the constants and string values for syslog severities.


