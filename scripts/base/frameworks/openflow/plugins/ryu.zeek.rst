:tocdepth: 3

base/frameworks/openflow/plugins/ryu.zeek
=========================================
.. zeek:namespace:: OpenFlow

OpenFlow plugin for the Ryu controller.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`, :doc:`base/utils/active-http.zeek </scripts/base/utils/active-http.zeek>`, :doc:`base/utils/exec.zeek </scripts/base/utils/exec.zeek>`, :doc:`base/utils/json.zeek </scripts/base/utils/json.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=============================================================================== =
:zeek:type:`OpenFlow::ControllerState`: :zeek:type:`record` :zeek:attr:`&redef` 
:zeek:type:`OpenFlow::Plugin`: :zeek:type:`enum`                                
=============================================================================== =

Functions
#########
=================================================== ===========================
:zeek:id:`OpenFlow::ryu_new`: :zeek:type:`function` Ryu controller constructor.
=================================================== ===========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: OpenFlow::ryu_new

   :Type: :zeek:type:`function` (host: :zeek:type:`addr`, host_port: :zeek:type:`count`, dpid: :zeek:type:`count`) : :zeek:type:`OpenFlow::Controller`

   Ryu controller constructor.
   

   :host: Controller ip.
   

   :host_port: Controller listen port.
   

   :dpid: OpenFlow switch datapath id.
   

   :returns: OpenFlow::Controller record.


