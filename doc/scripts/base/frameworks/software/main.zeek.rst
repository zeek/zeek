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

Redefinable Options
###################
==================================================================================== ====================================================================
:zeek:id:`Software::found_cache_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The framework maintains a redundancy cache in each worker that
                                                                                     deduplicates their version reporting in :zeek:see:`Software::found`.
:zeek:id:`Software::max_software_cache_size`: :zeek:type:`count` :zeek:attr:`&redef` For each software, each proxy maintains a per-host deduplication
                                                                                     cache of known versions that refreshes daily.
:zeek:id:`Software::parse_cache_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The framework maintains per-node caches that map unparsed version
                                                                                     strings to :zeek:type:`Software::Version` instances.
==================================================================================== ====================================================================

State Variables
###############
=========================================================================================================================== =========================================================
:zeek:id:`Software::alternate_names`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`                      Sometimes software will expose itself on the network with
                                                                                                                            slight naming variations.
:zeek:id:`Software::tracked`: :zeek:type:`table` :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&deprecated` = *...*
:zeek:id:`Software::tracked_software`: :zeek:type:`table` :zeek:attr:`&create_expire` = ``1.0 day``                         The set of software associated with an address.
=========================================================================================================================== =========================================================

Types
#####
======================================================================================= ======================================================================
:zeek:type:`Software::Info`: :zeek:type:`record`                                        The record type that is used for representing and logging software.
:zeek:type:`Software::Set`: :zeek:type:`record`                                         Type to represent a set of software versions of the same name,
                                                                                        tracking the most recent version explicitly.
:zeek:type:`Software::SoftwareSet`: :zeek:type:`table` :zeek:attr:`&deprecated` = *...*
:zeek:type:`Software::SoftwareSets`: :zeek:type:`table`                                 Type to represent a collection of :zeek:type:`Software::Info` records.
:zeek:type:`Software::Type`: :zeek:type:`enum`                                          Scripts detecting new types of software need to redef this enum to add
                                                                                        their own specific software types which would then be used when they
                                                                                        create :zeek:type:`Software::Info` records.
:zeek:type:`Software::Version`: :zeek:type:`record` :zeek:attr:`&log`                   A structure to represent the numeric version of software.
======================================================================================= ======================================================================

Redefinitions
#############
======================================= =======================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The software logging stream identifier.

                                        * :zeek:enum:`Software::LOG`
======================================= =======================================

Events
######
======================================================= ======================================================================
:zeek:id:`Software::log_software`: :zeek:type:`event`   This event can be handled to access the :zeek:type:`Software::Info`
                                                        record as it is sent on to the logging framework.
:zeek:id:`Software::register`: :zeek:type:`event`       This event is raised when software is about to be registered for
                                                        tracking in :zeek:see:`Software::tracked_software`.
:zeek:id:`Software::version_change`: :zeek:type:`event` This event can be handled to access software information whenever it's
                                                        version is found to have changed.
======================================================= ======================================================================

Hooks
#####
============================================================= =============================================
:zeek:id:`Software::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
============================================================= =============================================

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
   :source-code: base/frameworks/software/main.zeek 74 74

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``
   :Redefinition: from :doc:`/scripts/policy/tuning/track-all-assets.zeek`

      ``=``::

         ``ALL_HOSTS``


   Hosts whose software should be detected and tracked.
   Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.

Redefinable Options
###################
.. zeek:id:: Software::found_cache_interval
   :source-code: base/frameworks/software/main.zeek 84 84

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 mins``

   The framework maintains a redundancy cache in each worker that
   deduplicates their version reporting in :zeek:see:`Software::found`.
   This is its expiration interval. Setting to 0secs disables this cache.

.. zeek:id:: Software::max_software_cache_size
   :source-code: base/frameworks/software/main.zeek 90 90

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``20``

   For each software, each proxy maintains a per-host deduplication
   cache of known versions that refreshes daily. This setting caps the
   size of each of these caches. Exceeding the cap leads to a reset of
   the cache, and to redundant software.log writes. 0 disables the cap.

.. zeek:id:: Software::parse_cache_interval
   :source-code: base/frameworks/software/main.zeek 79 79

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min 5.0 secs``

   The framework maintains per-node caches that map unparsed version
   strings to :zeek:type:`Software::Version` instances. This is its
   expiration interval.

State Variables
###############
.. zeek:id:: Software::alternate_names
   :source-code: base/frameworks/software/main.zeek 114 114

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
   :source-code: base/frameworks/software/main.zeek 143 143

   :Type: :zeek:type:`table` [:zeek:type:`addr`] of :zeek:type:`Software::SoftwareSet`
   :Attributes: :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&deprecated` = *"Remove in v9.1. Unused. Use tracked_software instead."*
   :Default: ``{}``


.. zeek:id:: Software::tracked_software
   :source-code: base/frameworks/software/main.zeek 139 139

   :Type: :zeek:type:`table` [:zeek:type:`addr`] of :zeek:type:`Software::SoftwareSets`
   :Attributes: :zeek:attr:`&create_expire` = ``1.0 day``
   :Default: ``{}``

   The set of software associated with an address.  Data expires from
   this table after one day by default so that a detected piece of
   software will be logged once each day.  In a cluster, this table is
   uniformly distributed among proxy nodes.

Types
#####
.. zeek:type:: Software::Info
   :source-code: base/frameworks/software/main.zeek 43 70

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`

      The time at which the software was detected.


   .. zeek:field:: host :zeek:type:`addr` :zeek:attr:`&log`

      The IP address detected running the software.


   .. zeek:field:: host_p :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`

      The port on which the software is running. Only sensible for
      server software.


   .. zeek:field:: software_type :zeek:type:`Software::Type` :zeek:attr:`&log` :zeek:attr:`&default` = ``Software::UNKNOWN`` :zeek:attr:`&optional`

      The type of software detected (e.g. :zeek:enum:`HTTP::SERVER`).


   .. zeek:field:: name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Name of the software (e.g. Apache).


   .. zeek:field:: version :zeek:type:`Software::Version` :zeek:attr:`&log` :zeek:attr:`&optional`

      Version of the software.


   .. zeek:field:: unparsed_version :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The full unparsed version string found because the version
      parsing doesn't always work reliably in all cases and this
      acts as a fallback in the logs.


   .. zeek:field:: force_log :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      This can indicate that this software being detected should
      definitely be sent onward to the logging framework.  By
      default, only software that is "interesting" due to a change
      in version or it being currently unknown is sent to the
      logging framework.  This can be set to T to force the record
      to be sent to the logging framework if some amount of this
      tracking needs to happen in a specific way to the software.


   .. zeek:field:: url :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/policy/protocols/http/detect-webapps.zeek` is loaded)

      Most root URL where the software was discovered.


   The record type that is used for representing and logging software.

.. zeek:type:: Software::Set
   :source-code: base/frameworks/software/main.zeek 121 127

   :Type: :zeek:type:`record`


   .. zeek:field:: versions :zeek:type:`set` [:zeek:type:`string`]

      Set of version strings, unparsed when available (for full
      detail) or based on a :zeek:see:`Software::Version` record.


   .. zeek:field:: last :zeek:type:`Software::Info` :zeek:attr:`&optional`

      The most recent software info record for this set.


   Type to represent a set of software versions of the same name,
   tracking the most recent version explicitly.

.. zeek:type:: Software::SoftwareSet
   :source-code: base/frameworks/software/main.zeek 141 141

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Software::Info`
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v9.1. Use SoftwareSets instead."*


.. zeek:type:: Software::SoftwareSets
   :source-code: base/frameworks/software/main.zeek 133 133

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Software::Set`

   Type to represent a collection of :zeek:type:`Software::Info` records.
   It's indexed with the name of a piece of software such as "Firefox"
   and it yields a :zeek:type:`Software::Set` with specific versions
   of the software.

.. zeek:type:: Software::Type
   :source-code: base/frameworks/software/main.zeek 23 27

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
   :source-code: base/frameworks/software/main.zeek 29 40

   :Type: :zeek:type:`record`


   .. zeek:field:: major :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Major version number.


   .. zeek:field:: minor :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Minor version number.


   .. zeek:field:: minor2 :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Minor subversion number.


   .. zeek:field:: minor3 :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

      Minor updates number.


   .. zeek:field:: addl :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      Additional version string (e.g. "beta42").

   :Attributes: :zeek:attr:`&log`

   A structure to represent the numeric version of software.

Events
######
.. zeek:id:: Software::log_software
   :source-code: policy/frameworks/software/vulnerable.zeek 130 146

   :Type: :zeek:type:`event` (rec: :zeek:type:`Software::Info`)

   This event can be handled to access the :zeek:type:`Software::Info`
   record as it is sent on to the logging framework.

.. zeek:id:: Software::register
   :source-code: base/frameworks/software/main.zeek 156 156

   :Type: :zeek:type:`event` (info: :zeek:type:`Software::Info`)

   This event is raised when software is about to be registered for
   tracking in :zeek:see:`Software::tracked_software`.

.. zeek:id:: Software::version_change
   :source-code: policy/frameworks/software/version-changes.zeek 25 37

   :Type: :zeek:type:`event` (old: :zeek:type:`Software::Info`, new: :zeek:type:`Software::Info`)

   This event can be handled to access software information whenever it's
   version is found to have changed.

Hooks
#####
.. zeek:id:: Software::log_policy
   :source-code: base/frameworks/software/main.zeek 18 18

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

Functions
#########
.. zeek:id:: Software::cmp_versions
   :source-code: base/frameworks/software/main.zeek 410 486

   :Type: :zeek:type:`function` (v1: :zeek:type:`Software::Version`, v2: :zeek:type:`Software::Version`) : :zeek:type:`int`

   Compare two version records.


   :returns:  -1 for v1 < v2, 0 for v1 == v2, 1 for v1 > v2.
             If the numerical version numbers match, the *addl* string
             is compared lexicographically.

.. zeek:id:: Software::found
   :source-code: base/frameworks/software/main.zeek 583 620

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`, info: :zeek:type:`Software::Info`) : :zeek:type:`bool`

   Other scripts should call this function when they detect software.


   :param id: The connection id where the software was discovered.


   :param info: A record representing the software discovered.


   :returns: T if the software was logged, F otherwise.


