:tocdepth: 3

base/frameworks/software/main.zeek
==================================
.. bro:namespace:: Software

This script provides the framework for software version detection and
parsing but doesn't actually do any detection on it's own.  It relies on
other protocol specific scripts to parse out software from the protocols
that they analyze.  The entry point for providing new software detections
to this framework is through the :bro:id:`Software::found` function.

:Namespace: Software
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================= ====================================================
:bro:id:`Software::asset_tracking`: :bro:type:`Host` :bro:attr:`&redef` Hosts whose software should be detected and tracked.
======================================================================= ====================================================

State Variables
###############
======================================================================================================================== ==========================================================
:bro:id:`Software::alternate_names`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` Sometimes software will expose itself on the network with 
                                                                                                                         slight naming variations.
:bro:id:`Software::tracked`: :bro:type:`table` :bro:attr:`&create_expire` = ``1.0 day``                                  The set of software associated with an address.
======================================================================================================================== ==========================================================

Types
#####
================================================================== ======================================================================
:bro:type:`Software::Info`: :bro:type:`record`                     The record type that is used for representing and logging software.
:bro:type:`Software::SoftwareSet`: :bro:type:`table`               Type to represent a collection of :bro:type:`Software::Info` records.
:bro:type:`Software::Type`: :bro:type:`enum`                       Scripts detecting new types of software need to redef this enum to add
                                                                   their own specific software types which would then be used when they 
                                                                   create :bro:type:`Software::Info` records.
:bro:type:`Software::Version`: :bro:type:`record` :bro:attr:`&log` A structure to represent the numeric version of software.
================================================================== ======================================================================

Redefinitions
#############
===================================== =======================================
:bro:type:`Log::ID`: :bro:type:`enum` The software logging stream identifier.
===================================== =======================================

Events
######
===================================================== ======================================================================
:bro:id:`Software::log_software`: :bro:type:`event`   This event can be handled to access the :bro:type:`Software::Info`
                                                      record as it is sent on to the logging framework.
:bro:id:`Software::register`: :bro:type:`event`       This event is raised when software is about to be registered for
                                                      tracking in :bro:see:`Software::tracked`.
:bro:id:`Software::version_change`: :bro:type:`event` This event can be handled to access software information whenever it's
                                                      version is found to have changed.
===================================================== ======================================================================

Functions
#########
====================================================== ==================================================================
:bro:id:`Software::cmp_versions`: :bro:type:`function` Compare two version records.
:bro:id:`Software::found`: :bro:type:`function`        Other scripts should call this function when they detect software.
====================================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Software::asset_tracking

   :Type: :bro:type:`Host`
   :Attributes: :bro:attr:`&redef`
   :Default: ``ALL_HOSTS``

   Hosts whose software should be detected and tracked.
   Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.

State Variables
###############
.. bro:id:: Software::alternate_names

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
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

.. bro:id:: Software::tracked

   :Type: :bro:type:`table` [:bro:type:`addr`] of :bro:type:`Software::SoftwareSet`
   :Attributes: :bro:attr:`&create_expire` = ``1.0 day``
   :Default: ``{}``

   The set of software associated with an address.  Data expires from
   this table after one day by default so that a detected piece of 
   software will be logged once each day.  In a cluster, this table is
   uniformly distributed among proxy nodes.

Types
#####
.. bro:type:: Software::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         The time at which the software was detected.

      host: :bro:type:`addr` :bro:attr:`&log`
         The IP address detected running the software.

      host_p: :bro:type:`port` :bro:attr:`&log` :bro:attr:`&optional`
         The port on which the software is running. Only sensible for
         server software.

      software_type: :bro:type:`Software::Type` :bro:attr:`&log` :bro:attr:`&default` = ``Software::UNKNOWN`` :bro:attr:`&optional`
         The type of software detected (e.g. :bro:enum:`HTTP::SERVER`).

      name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Name of the software (e.g. Apache).

      version: :bro:type:`Software::Version` :bro:attr:`&log` :bro:attr:`&optional`
         Version of the software.

      unparsed_version: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The full unparsed version string found because the version
         parsing doesn't always work reliably in all cases and this
         acts as a fallback in the logs.

      force_log: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         This can indicate that this software being detected should
         definitely be sent onward to the logging framework.  By 
         default, only software that is "interesting" due to a change
         in version or it being currently unknown is sent to the
         logging framework.  This can be set to T to force the record
         to be sent to the logging framework if some amount of this
         tracking needs to happen in a specific way to the software.

      url: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         (present if :doc:`/scripts/policy/protocols/http/detect-webapps.zeek` is loaded)

         Most root URL where the software was discovered.

   The record type that is used for representing and logging software.

.. bro:type:: Software::SoftwareSet

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`Software::Info`

   Type to represent a collection of :bro:type:`Software::Info` records.
   It's indexed with the name of a piece of software such as "Firefox" 
   and it yields a :bro:type:`Software::Info` record with more
   information about the software.

.. bro:type:: Software::Type

   :Type: :bro:type:`enum`

      .. bro:enum:: Software::UNKNOWN Software::Type

         A placeholder type for when the type of software is not known.

      .. bro:enum:: OS::WINDOWS Software::Type

         (present if :doc:`/scripts/policy/frameworks/software/windows-version-detection.zeek` is loaded)


         Identifier for Windows operating system versions

      .. bro:enum:: DHCP::SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/dhcp/software.zeek` is loaded)


         Identifier for web servers in the software framework.

      .. bro:enum:: DHCP::CLIENT Software::Type

         (present if :doc:`/scripts/policy/protocols/dhcp/software.zeek` is loaded)


         Identifier for web browsers in the software framework.

      .. bro:enum:: FTP::CLIENT Software::Type

         (present if :doc:`/scripts/policy/protocols/ftp/software.zeek` is loaded)


         Identifier for FTP clients in the software framework.

      .. bro:enum:: FTP::SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/ftp/software.zeek` is loaded)


         Not currently implemented.

      .. bro:enum:: HTTP::WEB_APPLICATION Software::Type

         (present if :doc:`/scripts/policy/protocols/http/detect-webapps.zeek` is loaded)


         Identifier for web applications in the software framework.

      .. bro:enum:: HTTP::BROWSER_PLUGIN Software::Type

         (present if :doc:`/scripts/policy/protocols/http/software-browser-plugins.zeek` is loaded)


         Identifier for browser plugins in the software framework.

      .. bro:enum:: HTTP::SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/http/software.zeek` is loaded)


         Identifier for web servers in the software framework.

      .. bro:enum:: HTTP::APPSERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/http/software.zeek` is loaded)


         Identifier for app servers in the software framework.

      .. bro:enum:: HTTP::BROWSER Software::Type

         (present if :doc:`/scripts/policy/protocols/http/software.zeek` is loaded)


         Identifier for web browsers in the software framework.

      .. bro:enum:: MySQL::SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/mysql/software.zeek` is loaded)


         Identifier for MySQL servers in the software framework.

      .. bro:enum:: SMTP::MAIL_CLIENT Software::Type

         (present if :doc:`/scripts/policy/protocols/smtp/software.zeek` is loaded)


      .. bro:enum:: SMTP::MAIL_SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/smtp/software.zeek` is loaded)


      .. bro:enum:: SMTP::WEBMAIL_SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/smtp/software.zeek` is loaded)


      .. bro:enum:: SSH::SERVER Software::Type

         (present if :doc:`/scripts/policy/protocols/ssh/software.zeek` is loaded)


         Identifier for SSH clients in the software framework.

      .. bro:enum:: SSH::CLIENT Software::Type

         (present if :doc:`/scripts/policy/protocols/ssh/software.zeek` is loaded)


         Identifier for SSH servers in the software framework.

   Scripts detecting new types of software need to redef this enum to add
   their own specific software types which would then be used when they 
   create :bro:type:`Software::Info` records.

.. bro:type:: Software::Version

   :Type: :bro:type:`record`

      major: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Major version number.

      minor: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Minor version number.

      minor2: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Minor subversion number.

      minor3: :bro:type:`count` :bro:attr:`&optional` :bro:attr:`&log`
         Minor updates number.

      addl: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         Additional version string (e.g. "beta42").
   :Attributes: :bro:attr:`&log`

   A structure to represent the numeric version of software.

Events
######
.. bro:id:: Software::log_software

   :Type: :bro:type:`event` (rec: :bro:type:`Software::Info`)

   This event can be handled to access the :bro:type:`Software::Info`
   record as it is sent on to the logging framework.

.. bro:id:: Software::register

   :Type: :bro:type:`event` (info: :bro:type:`Software::Info`)

   This event is raised when software is about to be registered for
   tracking in :bro:see:`Software::tracked`.

.. bro:id:: Software::version_change

   :Type: :bro:type:`event` (old: :bro:type:`Software::Info`, new: :bro:type:`Software::Info`)

   This event can be handled to access software information whenever it's
   version is found to have changed.

Functions
#########
.. bro:id:: Software::cmp_versions

   :Type: :bro:type:`function` (v1: :bro:type:`Software::Version`, v2: :bro:type:`Software::Version`) : :bro:type:`int`

   Compare two version records.
   

   :returns:  -1 for v1 < v2, 0 for v1 == v2, 1 for v1 > v2.
             If the numerical version numbers match, the *addl* string
             is compared lexicographically.

.. bro:id:: Software::found

   :Type: :bro:type:`function` (id: :bro:type:`conn_id`, info: :bro:type:`Software::Info`) : :bro:type:`bool`

   Other scripts should call this function when they detect software.
   

   :id: The connection id where the software was discovered.
   

   :info: A record representing the software discovered.
   

   :returns: T if the software was logged, F otherwise.


