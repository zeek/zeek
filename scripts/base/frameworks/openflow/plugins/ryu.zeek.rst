:tocdepth: 3

base/frameworks/openflow/plugins/ryu.zeek
=========================================
.. bro:namespace:: OpenFlow

OpenFlow plugin for the Ryu controller.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`, :doc:`base/utils/active-http.zeek </scripts/base/utils/active-http.zeek>`, :doc:`base/utils/exec.zeek </scripts/base/utils/exec.zeek>`, :doc:`base/utils/json.zeek </scripts/base/utils/json.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================================================ =
:bro:type:`OpenFlow::ControllerState`: :bro:type:`record` :bro:attr:`&redef` 
:bro:type:`OpenFlow::Plugin`: :bro:type:`enum`                               
============================================================================ =

Functions
#########
================================================= ===========================
:bro:id:`OpenFlow::ryu_new`: :bro:type:`function` Ryu controller constructor.
================================================= ===========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: OpenFlow::ryu_new

   :Type: :bro:type:`function` (host: :bro:type:`addr`, host_port: :bro:type:`count`, dpid: :bro:type:`count`) : :bro:type:`OpenFlow::Controller`

   Ryu controller constructor.
   

   :host: Controller ip.
   

   :host_port: Controller listen port.
   

   :dpid: OpenFlow switch datapath id.
   

   :returns: OpenFlow::Controller record.


