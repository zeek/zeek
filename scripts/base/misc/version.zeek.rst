:tocdepth: 3

base/misc/version.zeek
======================
.. zeek:namespace:: Version

Provide information about the currently running Zeek version.
The most convenient way to access this are the Version::number
and Version::info constants.

:Namespace: Version
:Imports: :doc:`base/frameworks/reporter </scripts/base/frameworks/reporter/index>`, :doc:`base/utils/strings.zeek </scripts/base/utils/strings.zeek>`

Summary
~~~~~~~
Constants
#########
================================================================== ====================================================================================
:zeek:id:`Version::info`: :zeek:type:`Version::VersionDescription` `VersionDescription` record pertaining to the currently running version of Zeek.
:zeek:id:`Version::number`: :zeek:type:`count`                     version number of the currently running version of Zeek as a numeric representation.
================================================================== ====================================================================================

Types
#####
============================================================= ========================================
:zeek:type:`Version::VersionDescription`: :zeek:type:`record` A type exactly describing a Zeek version
============================================================= ========================================

Functions
#########
=================================================== ====================================================================================
:zeek:id:`Version::at_least`: :zeek:type:`function` Test if the current running version of Zeek is greater or equal to the given version
                                                    string.
:zeek:id:`Version::parse`: :zeek:type:`function`    Parse a given version string.
=================================================== ====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: Version::info

   :Type: :zeek:type:`Version::VersionDescription`

   `VersionDescription` record pertaining to the currently running version of Zeek.

.. zeek:id:: Version::number

   :Type: :zeek:type:`count`

   version number of the currently running version of Zeek as a numeric representation.
   The format of the number is ABBCC with A being the major version,
   bb being the minor version (2 digits) and CC being the patchlevel (2 digits).
   As an example, Zeek 2.4.1 results in the number 20401

Types
#####
.. zeek:type:: Version::VersionDescription

   :Type: :zeek:type:`record`

      version_number: :zeek:type:`count`
         Number representing the version which can be used for easy comparison.
         The format of the number is ABBCC with A being the major version,
         bb being the minor version (2 digits) and CC being the patchlevel (2 digits).
         As an example, Zeek 2.4.1 results in the number 20401.

      major: :zeek:type:`count`
         Major version number (e.g. 2 for 2.5)

      minor: :zeek:type:`count`
         Minor version number (e.g. 5 for 2.5)

      patch: :zeek:type:`count`
         Patch version number (e.g. 0 for 2.5 or 1 for 2.4.1)

      commit: :zeek:type:`count`
         Commit number for development versions, e.g. 12 for 2.4-12. 0 for non-development versions

      beta: :zeek:type:`bool`
         If set to true, the version is a beta build of Zeek

      debug: :zeek:type:`bool`
         If set to true, the version is a debug build

      version_string: :zeek:type:`string`
         String representation of this version

   A type exactly describing a Zeek version

Functions
#########
.. zeek:id:: Version::at_least

   :Type: :zeek:type:`function` (version_string: :zeek:type:`string`) : :zeek:type:`bool`

   Test if the current running version of Zeek is greater or equal to the given version
   string.
   

   :version_string: Version to check against the current running version.
   

   :returns: True if running version greater or equal to the given version.

.. zeek:id:: Version::parse

   :Type: :zeek:type:`function` (version_string: :zeek:type:`string`) : :zeek:type:`Version::VersionDescription`

   Parse a given version string.
   

   :version_string: Zeek version string.
   

   :returns: `VersionDescription` record.


