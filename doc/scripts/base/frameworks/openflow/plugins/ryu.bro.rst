:tocdepth: 3

base/frameworks/openflow/plugins/ryu.bro
========================================
.. bro:namespace:: OpenFlow

OpenFlow plugin for the Ryu controller.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`, :doc:`base/utils/active-http.bro </scripts/base/utils/active-http.bro>`, :doc:`base/utils/exec.bro </scripts/base/utils/exec.bro>`, :doc:`base/utils/json.bro </scripts/base/utils/json.bro>`

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


