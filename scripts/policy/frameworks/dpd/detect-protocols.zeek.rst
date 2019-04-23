:tocdepth: 3

policy/frameworks/dpd/detect-protocols.zeek
===========================================
.. zeek:namespace:: ProtocolDetector

Finds connections with protocols on non-standard ports with DPD.

:Namespace: ProtocolDetector
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`, :doc:`base/utils/site.zeek </scripts/base/utils/site.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================== =
:zeek:id:`ProtocolDetector::minimum_duration`: :zeek:type:`interval` :zeek:attr:`&redef` 
:zeek:id:`ProtocolDetector::minimum_volume`: :zeek:type:`double` :zeek:attr:`&redef`     
:zeek:id:`ProtocolDetector::suppress_servers`: :zeek:type:`set` :zeek:attr:`&redef`      
:zeek:id:`ProtocolDetector::valids`: :zeek:type:`table` :zeek:attr:`&redef`              
======================================================================================== =

Constants
#########
================================================================== =
:zeek:id:`ProtocolDetector::check_interval`: :zeek:type:`interval` 
================================================================== =

State Variables
###############
================================================================================================== =
:zeek:id:`ProtocolDetector::servers`: :zeek:type:`table` :zeek:attr:`&read_expire` = ``14.0 days`` 
================================================================================================== =

Types
#####
===================================================== =
:zeek:type:`ProtocolDetector::dir`: :zeek:type:`enum` 
===================================================== =

Redefinitions
#############
============================================ =
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
============================================ =

Functions
#########
================================================================== =
:zeek:id:`ProtocolDetector::found_protocol`: :zeek:type:`function` 
================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: ProtocolDetector::minimum_duration

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30.0 secs``


.. zeek:id:: ProtocolDetector::minimum_volume

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``4000.0``


.. zeek:id:: ProtocolDetector::suppress_servers

   :Type: :zeek:type:`set` [:zeek:type:`Analyzer::Tag`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``


.. zeek:id:: ProtocolDetector::valids

   :Type: :zeek:type:`table` [:zeek:type:`Analyzer::Tag`, :zeek:type:`addr`, :zeek:type:`port`] of :zeek:type:`ProtocolDetector::dir`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``


Constants
#########
.. zeek:id:: ProtocolDetector::check_interval

   :Type: :zeek:type:`interval`
   :Default: ``5.0 secs``


State Variables
###############
.. zeek:id:: ProtocolDetector::servers

   :Type: :zeek:type:`table` [:zeek:type:`addr`, :zeek:type:`port`, :zeek:type:`string`] of :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&read_expire` = ``14.0 days``
   :Default: ``{}``


Types
#####
.. zeek:type:: ProtocolDetector::dir

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ProtocolDetector::NONE ProtocolDetector::dir

      .. zeek:enum:: ProtocolDetector::INCOMING ProtocolDetector::dir

      .. zeek:enum:: ProtocolDetector::OUTGOING ProtocolDetector::dir

      .. zeek:enum:: ProtocolDetector::BOTH ProtocolDetector::dir


Functions
#########
.. zeek:id:: ProtocolDetector::found_protocol

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, atype: :zeek:type:`Analyzer::Tag`, protocol: :zeek:type:`string`) : :zeek:type:`void`



