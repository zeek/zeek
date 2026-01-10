:tocdepth: 3

policy/frameworks/management/controller/config.zeek
===================================================
.. zeek:namespace:: Management::Controller

Configuration settings for the cluster controller.

:Namespace: Management::Controller
:Imports: :doc:`policy/frameworks/management </scripts/policy/frameworks/management/index>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================================= =====================================================================================
:zeek:id:`Management::Controller::auto_assign_broker_ports`: :zeek:type:`bool` :zeek:attr:`&redef`                      Whether the controller should auto-assign Broker listening ports to
                                                                                                                        cluster nodes that need them and don't have them explicitly specified
                                                                                                                        in cluster configurations.
:zeek:id:`Management::Controller::auto_assign_broker_start_port`: :zeek:type:`port` :zeek:attr:`&redef`                 The TCP start port to use for auto-assigning cluster node listening
                                                                                                                        ports, if :zeek:see:`Management::Controller::auto_assign_broker_ports` is
                                                                                                                        enabled (the default) and nodes don't come with those ports assigned.
:zeek:id:`Management::Controller::auto_assign_metrics_ports`: :zeek:type:`bool` :zeek:attr:`&redef`                     Whether the controller should auto-assign metrics ports for Prometheus
                                                                                                                        to nodes that need them and don't have them explicitly specified in
                                                                                                                        their cluster configurations.
:zeek:id:`Management::Controller::auto_assign_metrics_start_port`: :zeek:type:`port` :zeek:attr:`&redef`                The TCP start port to use for auto-assigning metrics exposition ports
                                                                                                                        for Prometheus, if :zeek:see:`Management::Controller::auto_assign_metrics_ports`
                                                                                                                        is enabled (the default).
:zeek:id:`Management::Controller::default_port`: :zeek:type:`port` :zeek:attr:`&redef`                                  The fallback listen port if :zeek:see:`Management::Controller::listen_port`
                                                                                                                        remains empty.
:zeek:id:`Management::Controller::default_port_websocket`: :zeek:type:`port` :zeek:attr:`&redef`                        The fallback listen port if :zeek:see:`Management::Controller::listen_port_websocket`
                                                                                                                        remains empty.
:zeek:id:`Management::Controller::directory`: :zeek:type:`string` :zeek:attr:`&redef`                                   An optional custom output directory for stdout/stderr.
:zeek:id:`Management::Controller::listen_address`: :zeek:type:`string` :zeek:attr:`&redef`                              The network address the controller listens on for Broker clients.
:zeek:id:`Management::Controller::listen_address_websocket`: :zeek:type:`string` :zeek:attr:`&redef`                    The network address the controller listens on for websocket
                                                                                                                        clients.
:zeek:id:`Management::Controller::listen_port`: :zeek:type:`string` :zeek:attr:`&redef`                                 The network port the controller listens on for Broker clients.
:zeek:id:`Management::Controller::listen_port_websocket`: :zeek:type:`string` :zeek:attr:`&redef`                       The network port the controller listens on for websocket clients.
:zeek:id:`Management::Controller::name`: :zeek:type:`string` :zeek:attr:`&redef`                                        The name of this controller.
:zeek:id:`Management::Controller::stderr_file`: :zeek:type:`string` :zeek:attr:`&redef`                                 The controller's stderr log name.
:zeek:id:`Management::Controller::stdout_file`: :zeek:type:`string` :zeek:attr:`&redef`                                 The controller's stdout log name.
:zeek:id:`Management::Controller::tls_options_websocket`: :zeek:type:`Cluster::WebSocketTLSOptions` :zeek:attr:`&redef` TLS options for the controller's WebSocket server.
:zeek:id:`Management::Controller::topic`: :zeek:type:`string` :zeek:attr:`&redef`                                       The controller's Broker topic.
======================================================================================================================= =====================================================================================

Constants
#########
================================================================== ====================================================================
:zeek:id:`Management::Controller::store_name`: :zeek:type:`string` The name of the Broker store the controller uses to persist internal
                                                                   state to disk.
================================================================== ====================================================================

Functions
#########
================================================================================= ================================================================
:zeek:id:`Management::Controller::endpoint_info`: :zeek:type:`function`           Returns a :zeek:see:`Broker::EndpointInfo` record describing the
                                                                                  controller's Broker connectivity.
:zeek:id:`Management::Controller::endpoint_info_websocket`: :zeek:type:`function` Returns a :zeek:see:`Broker::EndpointInfo` record describing the
                                                                                  controller's websocket connectivity.
:zeek:id:`Management::Controller::get_name`: :zeek:type:`function`                Returns the effective name of the controller.
:zeek:id:`Management::Controller::network_info`: :zeek:type:`function`            Returns a :zeek:see:`Broker::NetworkInfo` record describing the
                                                                                  controller's Broker connectivity.
:zeek:id:`Management::Controller::network_info_websocket`: :zeek:type:`function`  Returns a :zeek:see:`Broker::NetworkInfo` record describing the
                                                                                  controller's websocket connectivity.
================================================================================= ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Management::Controller::auto_assign_broker_ports
   :source-code: policy/frameworks/management/controller/config.zeek 75 75

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether the controller should auto-assign Broker listening ports to
   cluster nodes that need them and don't have them explicitly specified
   in cluster configurations.

.. zeek:id:: Management::Controller::auto_assign_broker_start_port
   :source-code: policy/frameworks/management/controller/config.zeek 80 80

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2200/tcp``

   The TCP start port to use for auto-assigning cluster node listening
   ports, if :zeek:see:`Management::Controller::auto_assign_broker_ports` is
   enabled (the default) and nodes don't come with those ports assigned.

.. zeek:id:: Management::Controller::auto_assign_metrics_ports
   :source-code: policy/frameworks/management/controller/config.zeek 85 85

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether the controller should auto-assign metrics ports for Prometheus
   to nodes that need them and don't have them explicitly specified in
   their cluster configurations.

.. zeek:id:: Management::Controller::auto_assign_metrics_start_port
   :source-code: policy/frameworks/management/controller/config.zeek 90 90

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``9000/tcp``

   The TCP start port to use for auto-assigning metrics exposition ports
   for Prometheus, if :zeek:see:`Management::Controller::auto_assign_metrics_ports`
   is enabled (the default).

.. zeek:id:: Management::Controller::default_port
   :source-code: policy/frameworks/management/controller/config.zeek 44 44

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2150/tcp``

   The fallback listen port if :zeek:see:`Management::Controller::listen_port`
   remains empty. When set to 0/unknown, the controller won't listen
   for Broker connections. Don't do this if your management agents
   connect to the controller (instead of the default other way around),
   as they require Broker connectivity.

.. zeek:id:: Management::Controller::default_port_websocket
   :source-code: policy/frameworks/management/controller/config.zeek 62 62

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2149/tcp``

   The fallback listen port if :zeek:see:`Management::Controller::listen_port_websocket`
   remains empty. When set to 0/unknown, the controller won't listen
   for websocket clients.

.. zeek:id:: Management::Controller::directory
   :source-code: policy/frameworks/management/controller/config.zeek 99 99

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   An optional custom output directory for stdout/stderr. Agent and
   controller currently only log locally, not via the Zeek cluster's
   logger node. This means that if both write to the same log file,
   output gets garbled.

.. zeek:id:: Management::Controller::listen_address
   :source-code: policy/frameworks/management/controller/config.zeek 31 31

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network address the controller listens on for Broker clients. By
   default this uses the ZEEK_CONTROLLER_ADDR environment variable, but
   you may also redef to a specific value. When empty, the
   implementation falls back to :zeek:see:`Management::default_address`.

.. zeek:id:: Management::Controller::listen_address_websocket
   :source-code: policy/frameworks/management/controller/config.zeek 51 51

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network address the controller listens on for websocket
   clients. By default this uses the ZEEK_CONTROLLER_WEBSOCKET_ADDR
   environment variable, but you may also redef to a specific
   value. When empty, the implementation falls back to
   :zeek:see:`Management::default_address`.

.. zeek:id:: Management::Controller::listen_port
   :source-code: policy/frameworks/management/controller/config.zeek 37 37

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network port the controller listens on for Broker clients.
   Defaults to the ZEEK_CONTROLLER_PORT environment variable.
   When that is not set, the implementation falls back to
   :zeek:see:`Management::Controller::default_port`.

.. zeek:id:: Management::Controller::listen_port_websocket
   :source-code: policy/frameworks/management/controller/config.zeek 57 57

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network port the controller listens on for websocket clients.
   Defaults to the ZEEK_CONTROLLER_WEBSOCKET_PORT environment
   variable. When that is not set, the implementation falls back to
   :zeek:see:`Management::Controller::default_port_websocket`.

.. zeek:id:: Management::Controller::name
   :source-code: policy/frameworks/management/controller/config.zeek 12 12

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The name of this controller. Defaults to the value of the
   ZEEK_CONTROLLER_NAME environment variable. When that is unset and the
   user doesn't redef the value, the implementation defaults to
   "controller-<hostname>".

.. zeek:id:: Management::Controller::stderr_file
   :source-code: policy/frameworks/management/controller/config.zeek 25 25

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"stderr"``

   The controller's stderr log name. Like :zeek:see:`Management::Controller::stdout_file`,
   but for the stderr stream.

.. zeek:id:: Management::Controller::stdout_file
   :source-code: policy/frameworks/management/controller/config.zeek 21 21

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"stdout"``

   The controller's stdout log name. If the string is non-empty, Zeek
   will produce a free-form log (i.e., not one governed by Zeek's
   logging framework) in the controller's working directory. If left
   empty, no such log results.

   Note that the controller also establishes a "proper" Zeek log via the
   :zeek:see:`Management::Log` module.

.. zeek:id:: Management::Controller::tls_options_websocket
   :source-code: policy/frameworks/management/controller/config.zeek 70 70

   :Type: :zeek:type:`Cluster::WebSocketTLSOptions`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            cert_file=<uninitialized>
            key_file=<uninitialized>
            enable_peer_verification=F
            ca_file=""
            ciphers=""
         }


   TLS options for the controller's WebSocket server. The default is
   to operate unencrypted. To replicate Broker's default encryption
   without endpoint validation, set the
   :zeek:field:`Cluster::WebSocketTLSOptions$ca_file` field to
   "NONE" and :zeek:field:`Cluster::WebSocketTLSOptions$ciphers` to
   "AECDH-AES256-SHA@SECLEVEL=0:AECDH-AES256-SHA:P-384".

.. zeek:id:: Management::Controller::topic
   :source-code: policy/frameworks/management/controller/config.zeek 93 93

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/management/controller"``

   The controller's Broker topic. Clients send requests to this topic.

Constants
#########
.. zeek:id:: Management::Controller::store_name
   :source-code: policy/frameworks/management/controller/config.zeek 103 103

   :Type: :zeek:type:`string`
   :Default: ``"controller"``

   The name of the Broker store the controller uses to persist internal
   state to disk.

Functions
#########
.. zeek:id:: Management::Controller::endpoint_info
   :source-code: policy/frameworks/management/controller/config.zeek 171 179

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::EndpointInfo`

   Returns a :zeek:see:`Broker::EndpointInfo` record describing the
   controller's Broker connectivity.

.. zeek:id:: Management::Controller::endpoint_info_websocket
   :source-code: policy/frameworks/management/controller/config.zeek 181 189

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::EndpointInfo`

   Returns a :zeek:see:`Broker::EndpointInfo` record describing the
   controller's websocket connectivity.

.. zeek:id:: Management::Controller::get_name
   :source-code: policy/frameworks/management/controller/config.zeek 125 131

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Returns the effective name of the controller.

.. zeek:id:: Management::Controller::network_info
   :source-code: policy/frameworks/management/controller/config.zeek 133 150

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::NetworkInfo`

   Returns a :zeek:see:`Broker::NetworkInfo` record describing the
   controller's Broker connectivity.

.. zeek:id:: Management::Controller::network_info_websocket
   :source-code: policy/frameworks/management/controller/config.zeek 152 169

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::NetworkInfo`

   Returns a :zeek:see:`Broker::NetworkInfo` record describing the
   controller's websocket connectivity.


