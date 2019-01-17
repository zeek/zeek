:tocdepth: 3

base/frameworks/notice/actions/add-geodata.bro
==============================================
.. bro:namespace:: Notice

This script adds geographic location data to notices for the "remote"
host in a connection.  It does make the assumption that one of the 
addresses in a connection is "local" and one is "remote" which is 
probably a safe assumption to make in most cases.  If both addresses
are remote, it will use the $src address.

:Namespace: Notice
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/notice/main.bro </scripts/base/frameworks/notice/main.bro>`, :doc:`base/utils/site.bro </scripts/base/utils/site.bro>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================== ===============================================================
:bro:id:`Notice::lookup_location_types`: :bro:type:`set` :bro:attr:`&redef` Notice types which should have the "remote" location looked up.
=========================================================================== ===============================================================

Redefinitions
#############
============================================ =
:bro:type:`Notice::Action`: :bro:type:`enum` 
:bro:type:`Notice::Info`: :bro:type:`record` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Notice::lookup_location_types

   :Type: :bro:type:`set` [:bro:type:`Notice::Type`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Notice types which should have the "remote" location looked up.
   If GeoIP support is not built in, this does nothing.


