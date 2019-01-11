:tocdepth: 3

policy/protocols/dns/detect-external-names.bro
==============================================
.. bro:namespace:: DNS

This script detects names which are not within zones considered to be
local but resolving to addresses considered local.  
The :bro:id:`Site::local_zones` variable **must** be set appropriately for 
this detection.

:Namespace: DNS
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/utils/site.bro </scripts/base/utils/site.bro>`

Summary
~~~~~~~
Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

