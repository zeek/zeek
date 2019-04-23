:tocdepth: 3

base/frameworks/openflow/plugins/broker.zeek
============================================
.. zeek:namespace:: OpenFlow

OpenFlow plugin for interfacing to controllers via Broker.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`

Summary
~~~~~~~
Redefinitions
#############
=============================================================================== =
:zeek:type:`OpenFlow::ControllerState`: :zeek:type:`record` :zeek:attr:`&redef` 
:zeek:type:`OpenFlow::Plugin`: :zeek:type:`enum`                                
=============================================================================== =

Events
######
========================================================== =
:zeek:id:`OpenFlow::broker_flow_clear`: :zeek:type:`event` 
:zeek:id:`OpenFlow::broker_flow_mod`: :zeek:type:`event`   
========================================================== =

Functions
#########
====================================================== ==============================
:zeek:id:`OpenFlow::broker_new`: :zeek:type:`function` Broker controller constructor.
====================================================== ==============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: OpenFlow::broker_flow_clear

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, dpid: :zeek:type:`count`)


.. zeek:id:: OpenFlow::broker_flow_mod

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, dpid: :zeek:type:`count`, match: :zeek:type:`OpenFlow::ofp_match`, flow_mod: :zeek:type:`OpenFlow::ofp_flow_mod`)


Functions
#########
.. zeek:id:: OpenFlow::broker_new

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, host: :zeek:type:`addr`, host_port: :zeek:type:`port`, topic: :zeek:type:`string`, dpid: :zeek:type:`count`) : :zeek:type:`OpenFlow::Controller`

   Broker controller constructor.
   

   :host: Controller ip.
   

   :host_port: Controller listen port.
   

   :topic: Broker topic to send messages to.
   

   :dpid: OpenFlow switch datapath id.
   

   :returns: OpenFlow::Controller record.


