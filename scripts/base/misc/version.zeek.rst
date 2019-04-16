:tocdepth: 3

base/misc/version.zeek
======================
.. bro:namespace:: Version

Provide information about the currently running Bro version.
The most convenient way to access this are the Version::number
and Version::info constants.

:Namespace: Version
:Imports: :doc:`base/frameworks/reporter </scripts/base/frameworks/reporter/index>`, :doc:`base/utils/strings.zeek </scripts/base/utils/strings.zeek>`

Summary
~~~~~~~
Constants
#########
================================================================ ===================================================================================
:bro:id:`Version::info`: :bro:type:`Version::VersionDescription` `VersionDescription` record pertaining to the currently running version of Bro.
:bro:id:`Version::number`: :bro:type:`count`                     version number of the currently running version of Bro as a numeric representation.
================================================================ ===================================================================================

Types
#####
=========================================================== =======================================
:bro:type:`Version::VersionDescription`: :bro:type:`record` A type exactly describing a Bro version
=========================================================== =======================================

Functions
#########
================================================= ===================================================================================
:bro:id:`Version::at_least`: :bro:type:`function` Test if the current running version of Bro is greater or equal to the given version
                                                  string.
:bro:id:`Version::parse`: :bro:type:`function`    Parse a given version string.
================================================= ===================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. bro:id:: Version::info

   :Type: :bro:type:`Version::VersionDescription`

   `VersionDescription` record pertaining to the currently running version of Bro.

.. bro:id:: Version::number

   :Type: :bro:type:`count`

   version number of the currently running version of Bro as a numeric representation.
   The format of the number is ABBCC with A being the major version,
   bb being the minor version (2 digits) and CC being the patchlevel (2 digits).
   As an example, Bro 2.4.1 results in the number 20401

Types
#####
.. bro:type:: Version::VersionDescription

   :Type: :bro:type:`record`

      version_number: :bro:type:`count`
         Number representing the version which can be used for easy comparison.
         The format of the number is ABBCC with A being the major version,
         bb being the minor version (2 digits) and CC being the patchlevel (2 digits).
         As an example, Bro 2.4.1 results in the number 20401.

      major: :bro:type:`count`
         Major version number (e.g. 2 for 2.5)

      minor: :bro:type:`count`
         Minor version number (e.g. 5 for 2.5)

      patch: :bro:type:`count`
         Patch version number (e.g. 0 for 2.5 or 1 for 2.4.1)

      commit: :bro:type:`count`
         Commit number for development versions, e.g. 12 for 2.4-12. 0 for non-development versions

      beta: :bro:type:`bool`
         If set to true, the version is a beta build of Bro

      debug: :bro:type:`bool`
         If set to true, the version is a debug build

      version_string: :bro:type:`string`
         String representation of this version

   A type exactly describing a Bro version

Functions
#########
.. bro:id:: Version::at_least

   :Type: :bro:type:`function` (version_string: :bro:type:`string`) : :bro:type:`bool`

   Test if the current running version of Bro is greater or equal to the given version
   string.
   

   :version_string: Version to check against the current running version.
   

   :returns: True if running version greater or equal to the given version.

.. bro:id:: Version::parse

   :Type: :bro:type:`function` (version_string: :bro:type:`string`) : :bro:type:`Version::VersionDescription`

   Parse a given version string.
   

   :version_string: Bro version string.
   

   :returns: `VersionDescription` record.


