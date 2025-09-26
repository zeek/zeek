:tocdepth: 3

base/misc/find-checksum-offloading.zeek
=======================================
.. zeek:namespace:: ChecksumOffloading

Discover cases where the local interface is sniffed and outbound packets
have checksum offloading.  Load this script to receive a notice if it's
likely that checksum offload effects are being seen on a live interface or
in a packet trace file.

:Namespace: ChecksumOffloading
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================== =========================================================
:zeek:id:`ChecksumOffloading::check_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The interval which is used for checking packet statistics
                                                                                         to see if checksum offloading is affecting analysis.
======================================================================================== =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: ChecksumOffloading::check_interval
   :source-code: base/misc/find-checksum-offloading.zeek 13 13

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``

   The interval which is used for checking packet statistics
   to see if checksum offloading is affecting analysis.


