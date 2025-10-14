:tocdepth: 3

base/frameworks/control/main.zeek
=================================
.. zeek:namespace:: Control

The control framework provides the foundation for providing "commands"
that can be taken remotely at runtime to modify a running Zeek instance
or collect information from the running instance.

:Namespace: Control

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ ================================================================
:zeek:id:`Control::arg`: :zeek:type:`string` :zeek:attr:`&redef`             This can be used by commands that take an argument.
:zeek:id:`Control::cmd`: :zeek:type:`string` :zeek:attr:`&redef`             The command that is being done.
:zeek:id:`Control::commands`: :zeek:type:`set` :zeek:attr:`&redef`           The commands that can currently be given on the command line for
                                                                             remote control.
:zeek:id:`Control::controllee_listen`: :zeek:type:`bool` :zeek:attr:`&redef` Whether the controllee should call :zeek:see:`Broker::listen`.
:zeek:id:`Control::host`: :zeek:type:`addr` :zeek:attr:`&redef`              The address of the host that will be controlled.
:zeek:id:`Control::host_port`: :zeek:type:`port` :zeek:attr:`&redef`         The port of the host that will be controlled.
:zeek:id:`Control::zone_id`: :zeek:type:`string` :zeek:attr:`&redef`         If :zeek:id:`Control::host` is a non-global IPv6 address and
                                                                             requires a specific :rfc:`4007` ``zone_id``, it can be set here.
============================================================================ ================================================================

Constants
#########
===================================================== =================================================================
:zeek:id:`Control::ignore_ids`: :zeek:type:`set`      Variable IDs that are to be ignored by the update process.
:zeek:id:`Control::topic_prefix`: :zeek:type:`string` The topic prefix used for exchanging control messages via Broker.
===================================================== =================================================================

Events
######
===================================================================== =====================================================================
:zeek:id:`Control::configuration_update`: :zeek:type:`event`          This event is a wrapper and alias for the
                                                                      :zeek:id:`Control::configuration_update_request` event.
:zeek:id:`Control::configuration_update_request`: :zeek:type:`event`  Inform the remote Zeek instance that it's configuration may have been
                                                                      updated.
:zeek:id:`Control::configuration_update_response`: :zeek:type:`event` Message in response to a configuration update request.
:zeek:id:`Control::id_value_request`: :zeek:type:`event`              Event for requesting the value of an ID (a variable).
:zeek:id:`Control::id_value_response`: :zeek:type:`event`             Event for returning the value of an ID after an
                                                                      :zeek:id:`Control::id_value_request` event.
:zeek:id:`Control::net_stats_request`: :zeek:type:`event`             Requests the current net_stats.
:zeek:id:`Control::net_stats_response`: :zeek:type:`event`            Returns the current net_stats.
:zeek:id:`Control::peer_status_request`: :zeek:type:`event`           Requests the current communication status.
:zeek:id:`Control::peer_status_response`: :zeek:type:`event`          Returns the current communication status.
:zeek:id:`Control::shutdown_request`: :zeek:type:`event`              Requests that the Zeek instance begins shutting down.
:zeek:id:`Control::shutdown_response`: :zeek:type:`event`             Message in response to a shutdown request.
===================================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Control::arg
   :source-code: base/frameworks/control/main.zeek 30 30

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   This can be used by commands that take an argument.

.. zeek:id:: Control::cmd
   :source-code: base/frameworks/control/main.zeek 27 27

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The command that is being done.  It's typically set on the
   command line.

.. zeek:id:: Control::commands
   :source-code: base/frameworks/control/main.zeek 34 34

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "peer_status",
            "id_value",
            "net_stats",
            "configuration_update",
            "shutdown"
         }


   The commands that can currently be given on the command line for
   remote control.

.. zeek:id:: Control::controllee_listen
   :source-code: base/frameworks/control/main.zeek 13 13

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether the controllee should call :zeek:see:`Broker::listen`.
   In a cluster, this isn't needed since the setup process calls it.

.. zeek:id:: Control::host
   :source-code: base/frameworks/control/main.zeek 16 16

   :Type: :zeek:type:`addr`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0.0.0.0``

   The address of the host that will be controlled.

.. zeek:id:: Control::host_port
   :source-code: base/frameworks/control/main.zeek 19 19

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0/tcp``

   The port of the host that will be controlled.

.. zeek:id:: Control::zone_id
   :source-code: base/frameworks/control/main.zeek 23 23

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   If :zeek:id:`Control::host` is a non-global IPv6 address and
   requires a specific :rfc:`4007` ``zone_id``, it can be set here.

Constants
#########
.. zeek:id:: Control::ignore_ids
   :source-code: base/frameworks/control/main.zeek 43 43

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Default: ``{}``

   Variable IDs that are to be ignored by the update process.

.. zeek:id:: Control::topic_prefix
   :source-code: base/frameworks/control/main.zeek 9 9

   :Type: :zeek:type:`string`
   :Default: ``"zeek/control"``

   The topic prefix used for exchanging control messages via Broker.

Events
######
.. zeek:id:: Control::configuration_update
   :source-code: policy/frameworks/software/vulnerable.zeek 125 128

   :Type: :zeek:type:`event` ()

   This event is a wrapper and alias for the
   :zeek:id:`Control::configuration_update_request` event.
   This event is also a primary hooking point for the control framework.

.. zeek:id:: Control::configuration_update_request
   :source-code: policy/frameworks/control/controllee.zeek 67 77

   :Type: :zeek:type:`event` ()

   Inform the remote Zeek instance that it's configuration may have been
   updated.

.. zeek:id:: Control::configuration_update_response
   :source-code: policy/frameworks/control/controller.zeek 45 48

   :Type: :zeek:type:`event` ()

   Message in response to a configuration update request.

.. zeek:id:: Control::id_value_request
   :source-code: policy/frameworks/control/controllee.zeek 33 37

   :Type: :zeek:type:`event` (id: :zeek:type:`string`)

   Event for requesting the value of an ID (a variable).

.. zeek:id:: Control::id_value_response
   :source-code: policy/frameworks/control/controller.zeek 30 33

   :Type: :zeek:type:`event` (id: :zeek:type:`string`, val: :zeek:type:`string`)

   Event for returning the value of an ID after an
   :zeek:id:`Control::id_value_request` event.

.. zeek:id:: Control::net_stats_request
   :source-code: policy/frameworks/control/controllee.zeek 59 65

   :Type: :zeek:type:`event` ()

   Requests the current net_stats.

.. zeek:id:: Control::net_stats_response
   :source-code: policy/frameworks/control/controller.zeek 40 43

   :Type: :zeek:type:`event` (s: :zeek:type:`string`)

   Returns the current net_stats.

.. zeek:id:: Control::peer_status_request
   :source-code: policy/frameworks/control/controllee.zeek 39 57

   :Type: :zeek:type:`event` ()

   Requests the current communication status.

.. zeek:id:: Control::peer_status_response
   :source-code: policy/frameworks/control/controller.zeek 35 38

   :Type: :zeek:type:`event` (s: :zeek:type:`string`)

   Returns the current communication status.

.. zeek:id:: Control::shutdown_request
   :source-code: policy/frameworks/control/controllee.zeek 79 85

   :Type: :zeek:type:`event` ()

   Requests that the Zeek instance begins shutting down.

.. zeek:id:: Control::shutdown_response
   :source-code: policy/frameworks/control/controller.zeek 50 53

   :Type: :zeek:type:`event` ()

   Message in response to a shutdown request.


