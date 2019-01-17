:tocdepth: 3

policy/frameworks/dpd/detect-protocols.bro
==========================================
.. bro:namespace:: ProtocolDetector

Finds connections with protocols on non-standard ports with DPD.

:Namespace: ProtocolDetector
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/utils/conn-ids.bro </scripts/base/utils/conn-ids.bro>`, :doc:`base/utils/site.bro </scripts/base/utils/site.bro>`

Summary
~~~~~~~
Runtime Options
###############
===================================================================================== =
:bro:id:`ProtocolDetector::minimum_duration`: :bro:type:`interval` :bro:attr:`&redef` 
:bro:id:`ProtocolDetector::minimum_volume`: :bro:type:`double` :bro:attr:`&redef`     
:bro:id:`ProtocolDetector::suppress_servers`: :bro:type:`set` :bro:attr:`&redef`      
:bro:id:`ProtocolDetector::valids`: :bro:type:`table` :bro:attr:`&redef`              
===================================================================================== =

Constants
#########
================================================================ =
:bro:id:`ProtocolDetector::check_interval`: :bro:type:`interval` 
================================================================ =

State Variables
###############
=============================================================================================== =
:bro:id:`ProtocolDetector::servers`: :bro:type:`table` :bro:attr:`&read_expire` = ``14.0 days`` 
=============================================================================================== =

Types
#####
=================================================== =
:bro:type:`ProtocolDetector::dir`: :bro:type:`enum` 
=================================================== =

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =

Functions
#########
================================================================ =
:bro:id:`ProtocolDetector::found_protocol`: :bro:type:`function` 
================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: ProtocolDetector::minimum_duration

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``30.0 secs``


.. bro:id:: ProtocolDetector::minimum_volume

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``4000.0``


.. bro:id:: ProtocolDetector::suppress_servers

   :Type: :bro:type:`set` [:bro:type:`Analyzer::Tag`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``


.. bro:id:: ProtocolDetector::valids

   :Type: :bro:type:`table` [:bro:type:`Analyzer::Tag`, :bro:type:`addr`, :bro:type:`port`] of :bro:type:`ProtocolDetector::dir`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``


Constants
#########
.. bro:id:: ProtocolDetector::check_interval

   :Type: :bro:type:`interval`
   :Default: ``5.0 secs``


State Variables
###############
.. bro:id:: ProtocolDetector::servers

   :Type: :bro:type:`table` [:bro:type:`addr`, :bro:type:`port`, :bro:type:`string`] of :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&read_expire` = ``14.0 days``
   :Default: ``{}``


Types
#####
.. bro:type:: ProtocolDetector::dir

   :Type: :bro:type:`enum`

      .. bro:enum:: ProtocolDetector::NONE ProtocolDetector::dir

      .. bro:enum:: ProtocolDetector::INCOMING ProtocolDetector::dir

      .. bro:enum:: ProtocolDetector::OUTGOING ProtocolDetector::dir

      .. bro:enum:: ProtocolDetector::BOTH ProtocolDetector::dir


Functions
#########
.. bro:id:: ProtocolDetector::found_protocol

   :Type: :bro:type:`function` (c: :bro:type:`connection`, atype: :bro:type:`Analyzer::Tag`, protocol: :bro:type:`string`) : :bro:type:`void`



