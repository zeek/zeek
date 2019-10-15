:tocdepth: 3

base/frameworks/software/main.zeek
==================================
.. zeek:namespace:: Software

This script provides the framework for software version detection and
parsing but doesn't actually do any detection on it's own.  It relies on
other protocol specific scripts to parse out software from the protocols
that they analyze.  The entry point for providing new software detections
to this framework is through the :zeek:id:`Software::found` function.

:Namespace: Software
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================== ====================================================
:zeek:id:`Software::asset_tracking`: :zeek:type:`Host` :zeek:attr:`&redef` Hosts whose software should be detected and tracked.
========================================================================== ====================================================

State Variables
###############
====================================================================================================== ==========================================================
:zeek:id:`Software::alternate_names`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` Sometimes software will expose itself on the network with 
                                                                                                       slight naming variations.
:zeek:id:`Software::tracked`: :zeek:type:`table` :zeek:attr:`&create_expire` = ``1.0 day``             The set of software associated with an address.
====================================================================================================== ==========================================================

Types
#####
===================================================================== ======================================================================
:zeek:type:`Software::Info`: :zeek:type:`record`                      The record type that is used for representing and logging software.
:zeek:type:`Software::SoftwareSet`: :zeek:type:`table`                Type to represent a collection of :zeek:type:`Software::Info` records.
:zeek:type:`Software::Type`: :zeek:type:`enum`                        Scripts detecting new types of software need to redef this enum to add
                                                                      their own specific software types which would then be used when they 
                                                                      create :zeek:type:`Software::Info` records.
:zeek:type:`Software::Version`: :zeek:type:`record` :zeek:attr:`&log` A structure to represent the numeric version of software.
===================================================================== ======================================================================

Redefinitions
#############
======================================= =======================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The software logging stream identifier.
======================================= =======================================

Events
######
======================================================= ======================================================================
:zeek:id:`Software::log_software`: :zeek:type:`event`   This event can be handled to access the :zeek:type:`Software::Info`
                                                        record as it is sent on to the logging framework.
:zeek:id:`Software::register`: :zeek:type:`event`       This event is raised when software is about to be registered for
                                                        tracking in :zeek:see:`Software::tracked`.
:zeek:id:`Software::version_change`: :zeek:type:`event` This event can be handled to access software information whenever it's
                                                        version is found to have changed.
======================================================= ======================================================================

Functions
#########
======================================================== ==================================================================
:zeek:id:`Software::cmp_versions`: :zeek:type:`function` Compare two version records.
:zeek:id:`Software::found`: :zeek:type:`function`        Other scripts should call this function when they detect software.
======================================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Software::asset_tracking

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``
   :Redefinition: from :doc:`/scripts/policy/tuning/track-all-assets.zeek`

      ``=``::

         ALL_HOSTS


   Hosts whose software should be detected and tracked.
   Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.

State Variables
###############
.. zeek:id:: Software::alternate_names

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            ["Flash Player"] = "Flash"
         }


   Sometimes software will expose itself on the network with 
   slight naming variations.  This table provides a mechanism 
   for a piece of software to be renamed to a single name 
   even if it exposes itself with an alternate name.  The 
   yielded string is the name that will be logged and generally
   used for everything.

.. zeek:id:: Software::tracked

   :Type: :zeek:type:`table` [:zeek:type:`addr`] of :zeek:type:`Software::SoftwareSet`
   :Attributes: :zeek:attr:`&create_expire` = ``1.0 day``
   :Default: ``{}``

   The set of software associated with an address.  Data expires from
   this table after one day by default so that a detected piece of 
   software will be logged once each day.  In a cluster, this table is
   uniformly distributed among proxy nodes.

Types
#####
.. zeek:type:: Software::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`
         The time at which the software was detected.

      host: :zeek:type:`addr` :zeek:attr:`&log`
         The IP address detected running the software.

      host_p: :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`
         The port on which the software is running. Only sensible for
         server software.

      software_type: :zeek:type:`Software::Type` :zeek:attr:`&log` :zeek:attr:`&default` = ``Software::UNKNOWN`` :zeek:attr:`&optional`
         The type of software detected (e.g. :zeek:enum:`HTTP::SERVER`).

      name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Name of the software (e.g. Apache).

      version: :zeek:type:`Software::Version` :zeek:attr:`&log` :zeek:attr:`&optional`
         Version of the software.

      unparsed_version: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The full unparsed version string found because the version
         parsing doesn't always work reliably in all cases and this
         acts as a fallback in the logs.

      force_log: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         This can indicate that this software being detected should
         definitely be sent onward to the logging framework.  By 
         default, only software that is "interesting" due to a change
         in version or it being currently unknown is sent to the
         logging framework.  This can be set to T to force the record
         to be sent to the logging framework if some amount of this
         tracking needs to happen in a specific way to the software.

      url: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         (present if :doc:`/scripts/policy/protocols/http/detect-webapps.zeek` is loaded)

         Most root URL where the software was discovered.

   The record type that is used for representing and logging software.

.. zeek:type:: Software::SoftwareSet

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Software::Info`

   Type to represent a collection of :zeek:type:`Software::Info` records.
   It's indexed with the name of a piece of software such as "Firefox" 
   and it yields a :zeek:type:`Software::Info` record with more
   information about the software.

.. zeek:type:: Software::Type

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Software::UNKNOWN Software::Type

         A placeholder type for when the type of software is not known.

      .. zeek:enum:: OS::WINDOWS Software::Type

         (present if :doc:`/scripts/policy/frameworks/software/windows-version-detection.zeek` is loaded)


         Identifier for Windows operating system versions

      .. zeek:enum:: DHCP::SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/dhcp/software.zeek` is loaded)


         Identifier for web servers in the software framework.

      .. zeek:enum:: DHCP::CLIENT Software::Type

         (present if :doc:`/scripts/policy/protocols/dhcp/software.zeek` is loaded)


         Identifier for web browsers in the software framework.

      .. zeek:enum:: FTP::CLIENT Software::Type

         (present if :doc:`/scripts/policy/protocols/ftp/software.zeek` is loaded)


         Identifier for FTP clients in the software framework.

      .. zeek:enum:: FTP::SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/ftp/software.zeek` is loaded)


         Not currently implemented.

      .. zeek:enum:: HTTP::WEB_APPLICATION Software::Type

         (present if :doc:`/scripts/policy/protocols/http/detect-webapps.zeek` is loaded)


         Identifier for web applications in the software framework.

      .. zeek:enum:: HTTP::BROWSER_PLUGIN Software::Type

         (present if :doc:`/scripts/policy/protocols/http/software-browser-plugins.zeek` is loaded)


         Identifier for browser plugins in the software framework.

      .. zeek:enum:: HTTP::SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/http/software.zeek` is loaded)


         Identifier for web servers in the software framework.

      .. zeek:enum:: HTTP::APPSERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/http/software.zeek` is loaded)


         Identifier for app servers in the software framework.

      .. zeek:enum:: HTTP::BROWSER Software::Type

         (present if :doc:`/scripts/policy/protocols/http/software.zeek` is loaded)


         Identifier for web browsers in the software framework.

      .. zeek:enum:: MySQL::SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/mysql/software.zeek` is loaded)


         Identifier for MySQL servers in the software framework.

      .. zeek:enum:: SMTP::MAIL_CLIENT Software::Type

         (present if :doc:`/scripts/policy/protocols/smtp/software.zeek` is loaded)


      .. zeek:enum:: SMTP::MAIL_SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/smtp/software.zeek` is loaded)


      .. zeek:enum:: SMTP::WEBMAIL_SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/smtp/software.zeek` is loaded)


      .. zeek:enum:: SSH::SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/ssh/software.zeek` is loaded)


         Identifier for SSH clients in the software framework.

      .. zeek:enum:: SSH::CLIENT Software::Type

         (present if :doc:`/scripts/policy/protocols/ssh/software.zeek` is loaded)


         Identifier for SSH servers in the software framework.

   Scripts detecting new types of software need to redef this enum to add
   their own specific software types which would then be used when they 
   create :zeek:type:`Software::Info` records.

.. zeek:type:: Software::Version

   :Type: :zeek:type:`record`

      major: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Major version number.

      minor: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Minor version number.

      minor2: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Minor subversion number.

      minor3: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
         Minor updates number.

      addl: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         Additional version string (e.g. "beta42").
   :Attributes: :zeek:attr:`&log`

   A structure to represent the numeric version of software.

Events
######
.. zeek:id:: Software::log_software

   :Type: :zeek:type:`event` (rec: :zeek:type:`Software::Info`)

   This event can be handled to access the :zeek:type:`Software::Info`
   record as it is sent on to the logging framework.

.. zeek:id:: Software::register

   :Type: :zeek:type:`event` (info: :zeek:type:`Software::Info`)

   This event is raised when software is about to be registered for
   tracking in :zeek:see:`Software::tracked`.

.. zeek:id:: Software::version_change

   :Type: :zeek:type:`event` (old: :zeek:type:`Software::Info`, new: :zeek:type:`Software::Info`)

   This event can be handled to access software information whenever it's
   version is found to have changed.

Functions
#########
.. zeek:id:: Software::cmp_versions

   :Type: :zeek:type:`function` (v1: :zeek:type:`Software::Version`, v2: :zeek:type:`Software::Version`) : :zeek:type:`int`

   Compare two version records.
   

   :returns:  -1 for v1 < v2, 0 for v1 == v2, 1 for v1 > v2.
             If the numerical version numbers match, the *addl* string
             is compared lexicographically.

.. zeek:id:: Software::found

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`, info: :zeek:type:`Software::Info`) : :zeek:type:`bool`

   Other scripts should call this function when they detect software.
   

   :id: The connection id where the software was discovered.
   

   :info: A record representing the software discovered.
   

   :returns: T if the software was logged, F otherwise.


