:tocdepth: 3

base/frameworks/openflow/plugins/broker.bro
===========================================
.. bro:namespace:: OpenFlow

OpenFlow plugin for interfacing to controllers via Broker.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================================================ =
:bro:type:`OpenFlow::ControllerState`: :bro:type:`record` :bro:attr:`&redef` 
:bro:type:`OpenFlow::Plugin`: :bro:type:`enum`                               
============================================================================ =

Events
######
======================================================== =
:bro:id:`OpenFlow::broker_flow_clear`: :bro:type:`event` 
:bro:id:`OpenFlow::broker_flow_mod`: :bro:type:`event`   
======================================================== =

Functions
#########
==================================================== ==============================
:bro:id:`OpenFlow::broker_new`: :bro:type:`function` Broker controller constructor.
==================================================== ==============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: OpenFlow::broker_flow_clear

   :Type: :bro:type:`event` (name: :bro:type:`string`, dpid: :bro:type:`count`)


.. bro:id:: OpenFlow::broker_flow_mod

   :Type: :bro:type:`event` (name: :bro:type:`string`, dpid: :bro:type:`count`, match: :bro:type:`OpenFlow::ofp_match`, flow_mod: :bro:type:`OpenFlow::ofp_flow_mod`)


Functions
#########
.. bro:id:: OpenFlow::broker_new

   :Type: :bro:type:`function` (name: :bro:type:`string`, host: :bro:type:`addr`, host_port: :bro:type:`port`, topic: :bro:type:`string`, dpid: :bro:type:`count`) : :bro:type:`OpenFlow::Controller`

   Broker controller constructor.
   

   :host: Controller ip.
   

   :host_port: Controller listen port.
   

   :topic: Broker topic to send messages to.
   

   :dpid: OpenFlow switch datapath id.
   

   :returns: OpenFlow::Controller record.


