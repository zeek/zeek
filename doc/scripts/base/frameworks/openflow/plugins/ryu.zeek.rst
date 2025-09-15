:tocdepth: 3

base/frameworks/openflow/plugins/ryu.zeek
=========================================
.. zeek:namespace:: OpenFlow

OpenFlow plugin for the Ryu controller.

:Namespace: OpenFlow
:Imports: :doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`, :doc:`base/utils/active-http.zeek </scripts/base/utils/active-http.zeek>`, :doc:`base/utils/exec.zeek </scripts/base/utils/exec.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=============================================================================== ===================================================================================
:zeek:type:`OpenFlow::ControllerState`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                                                
                                                                                :New Fields: :zeek:type:`OpenFlow::ControllerState`
                                                                                
                                                                                  ryu_host: :zeek:type:`addr` :zeek:attr:`&optional`
                                                                                    Controller ip.
                                                                                
                                                                                  ryu_port: :zeek:type:`count` :zeek:attr:`&optional`
                                                                                    Controller listen port.
                                                                                
                                                                                  ryu_dpid: :zeek:type:`count` :zeek:attr:`&optional`
                                                                                    OpenFlow switch datapath id.
                                                                                
                                                                                  ryu_debug: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                                                    Enable debug mode - output JSON to stdout; do not perform actions.
:zeek:type:`OpenFlow::Plugin`: :zeek:type:`enum`                                
                                                                                
                                                                                * :zeek:enum:`OpenFlow::RYU`
=============================================================================== ===================================================================================

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
   :source-code: base/frameworks/openflow/plugins/ryu.zeek 181 189

   :Type: :zeek:type:`function` (host: :zeek:type:`addr`, host_port: :zeek:type:`count`, dpid: :zeek:type:`count`) : :zeek:type:`OpenFlow::Controller`

   Ryu controller constructor.
   

   :param host: Controller ip.
   

   :param host_port: Controller listen port.
   

   :param dpid: OpenFlow switch datapath id.
   

   :returns: OpenFlow::Controller record.


