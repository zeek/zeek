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
=============================================================================== ==========================================================
:zeek:type:`OpenFlow::ControllerState`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                                                
                                                                                :New Fields: :zeek:type:`OpenFlow::ControllerState`
                                                                                
                                                                                  broker_host: :zeek:type:`addr` :zeek:attr:`&optional`
                                                                                    Controller ip.
                                                                                
                                                                                  broker_port: :zeek:type:`port` :zeek:attr:`&optional`
                                                                                    Controller listen port.
                                                                                
                                                                                  broker_dpid: :zeek:type:`count` :zeek:attr:`&optional`
                                                                                    OpenFlow switch datapath id.
                                                                                
                                                                                  broker_topic: :zeek:type:`string` :zeek:attr:`&optional`
                                                                                    Topic to send events for this controller to.
:zeek:type:`OpenFlow::Plugin`: :zeek:type:`enum`                                
                                                                                
                                                                                * :zeek:enum:`OpenFlow::BROKER`
=============================================================================== ==========================================================

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
   :source-code: base/frameworks/openflow/plugins/broker.zeek 38 38

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, dpid: :zeek:type:`count`)


.. zeek:id:: OpenFlow::broker_flow_mod
   :source-code: base/frameworks/openflow/plugins/broker.zeek 37 37

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, dpid: :zeek:type:`count`, match: :zeek:type:`OpenFlow::ofp_match`, flow_mod: :zeek:type:`OpenFlow::ofp_flow_mod`)


Functions
#########
.. zeek:id:: OpenFlow::broker_new
   :source-code: base/frameworks/openflow/plugins/broker.zeek 82 95

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, host: :zeek:type:`addr`, host_port: :zeek:type:`port`, topic: :zeek:type:`string`, dpid: :zeek:type:`count`) : :zeek:type:`OpenFlow::Controller`

   Broker controller constructor.
   

   :param host: Controller ip.
   

   :param host_port: Controller listen port.
   

   :param topic: Broker topic to send messages to.
   

   :param dpid: OpenFlow switch datapath id.
   

   :returns: OpenFlow::Controller record.


