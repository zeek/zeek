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
Runtime Options
###############
=============================================================================== =====================================
:zeek:id:`DNS::skip_resp_host_port_pairs`: :zeek:type:`set` :zeek:attr:`&redef` Default is to ignore mDNS broadcasts.
=============================================================================== =====================================

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
Runtime Options
###############
.. zeek:id:: DNS::skip_resp_host_port_pairs
   :source-code: policy/protocols/dns/detect-external-names.zeek 20 20

   :Type: :zeek:type:`set` [:zeek:type:`addr`, :zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            [224.0.0.251, 5353/udp],
            [ff02::fb, 5353/udp]
         }


   Default is to ignore mDNS broadcasts.


