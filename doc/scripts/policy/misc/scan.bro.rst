:tocdepth: 3

policy/misc/scan.bro
====================
.. bro:namespace:: Scan

TCP Scan detection.

:Namespace: Scan
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/utils/time.bro </scripts/base/utils/time.bro>`

Summary
~~~~~~~
Redefinable Options
###################
=========================================================================== ==================================================================
:bro:id:`Scan::addr_scan_interval`: :bro:type:`interval` :bro:attr:`&redef` Failed connection attempts are tracked over this time interval for
                                                                            the address scan detection.
:bro:id:`Scan::addr_scan_threshold`: :bro:type:`double` :bro:attr:`&redef`  The threshold of the unique number of hosts a scanning host has to
                                                                            have failed connections with on a single port.
:bro:id:`Scan::port_scan_interval`: :bro:type:`interval` :bro:attr:`&redef` Failed connection attempts are tracked over this time interval for
                                                                            the port scan detection.
:bro:id:`Scan::port_scan_threshold`: :bro:type:`double` :bro:attr:`&redef`  The threshold of the number of unique ports a scanning host has to
                                                                            have failed connections with on a single victim host.
=========================================================================== ==================================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =

Hooks
#####
================================================== =
:bro:id:`Scan::addr_scan_policy`: :bro:type:`hook` 
:bro:id:`Scan::port_scan_policy`: :bro:type:`hook` 
================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Scan::addr_scan_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 mins``

   Failed connection attempts are tracked over this time interval for
   the address scan detection.  A higher interval will detect slower
   scanners, but may also yield more false positives.

.. bro:id:: Scan::addr_scan_threshold

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``25.0``

   The threshold of the unique number of hosts a scanning host has to
   have failed connections with on a single port.

.. bro:id:: Scan::port_scan_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``5.0 mins``

   Failed connection attempts are tracked over this time interval for
   the port scan detection.  A higher interval will detect slower
   scanners, but may also yield more false positives.

.. bro:id:: Scan::port_scan_threshold

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15.0``

   The threshold of the number of unique ports a scanning host has to
   have failed connections with on a single victim host.

Hooks
#####
.. bro:id:: Scan::addr_scan_policy

   :Type: :bro:type:`hook` (scanner: :bro:type:`addr`, victim: :bro:type:`addr`, scanned_port: :bro:type:`port`) : :bro:type:`bool`


.. bro:id:: Scan::port_scan_policy

   :Type: :bro:type:`hook` (scanner: :bro:type:`addr`, victim: :bro:type:`addr`, scanned_port: :bro:type:`port`) : :bro:type:`bool`



