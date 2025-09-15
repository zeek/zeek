:tocdepth: 3

base/frameworks/notice/actions/add-geodata.zeek
===============================================
.. zeek:namespace:: Notice

This script adds geographic location data to notices for the "remote"
host in a connection.  It does make the assumption that one of the
addresses in a connection is "local" and one is "remote" which is
probably a safe assumption to make in most cases.  If both addresses
are remote, it will use the $src address.

:Namespace: Notice
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/notice/main.zeek </scripts/base/frameworks/notice/main.zeek>`, :doc:`base/utils/site.zeek </scripts/base/utils/site.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================== ===============================================================
:zeek:id:`Notice::lookup_location_types`: :zeek:type:`set` :zeek:attr:`&redef` Notice types which should have the "remote" location looked up.
============================================================================== ===============================================================

Redefinitions
#############
============================================== =====================================================================================
:zeek:type:`Notice::Action`: :zeek:type:`enum` 
                                               
                                               * :zeek:enum:`Notice::ACTION_ADD_GEODATA`:
                                                 Indicates that the notice should have geodata added for the
                                                 "remote" host.
:zeek:type:`Notice::Info`: :zeek:type:`record` 
                                               
                                               :New Fields: :zeek:type:`Notice::Info`
                                               
                                                 remote_location: :zeek:type:`geo_location` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                   If GeoIP support is built in, notices can have geographic
                                                   information attached to them.
============================================== =====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Notice::lookup_location_types
   :source-code: base/frameworks/notice/actions/add-geodata.zeek 29 29

   :Type: :zeek:type:`set` [:zeek:type:`Notice::Type`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Notice types which should have the "remote" location looked up.
   If GeoIP support is not built in, this does nothing.


