:tocdepth: 3

policy/protocols/dns/detect-external-names.zeek
===============================================
.. zeek:namespace:: DNS

This script detects names which are not within zones considered to be
local but resolving to addresses considered local.
The :zeek:id:`Site::local_zones` variable **must** be set appropriately for
this detection.

:Namespace: DNS
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/utils/site.zeek </scripts/base/utils/site.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================ ===========================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`DNS::External_Name`:
                                               Raised when a non-local name is found to be pointing at a
                                               local host.
============================================ ===========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

