:tocdepth: 3

base/frameworks/control/main.bro
================================
.. bro:namespace:: Control

The control framework provides the foundation for providing "commands"
that can be taken remotely at runtime to modify a running Bro instance
or collect information from the running instance.

:Namespace: Control

Summary
~~~~~~~
Redefinable Options
###################
========================================================================= ================================================================
:bro:id:`Control::arg`: :bro:type:`string` :bro:attr:`&redef`             This can be used by commands that take an argument.
:bro:id:`Control::cmd`: :bro:type:`string` :bro:attr:`&redef`             The command that is being done.
:bro:id:`Control::commands`: :bro:type:`set` :bro:attr:`&redef`           The commands that can currently be given on the command line for
                                                                          remote control.
:bro:id:`Control::controllee_listen`: :bro:type:`bool` :bro:attr:`&redef` Whether the controllee should call :bro:see:`Broker::listen`.
:bro:id:`Control::host`: :bro:type:`addr` :bro:attr:`&redef`              The address of the host that will be controlled.
:bro:id:`Control::host_port`: :bro:type:`port` :bro:attr:`&redef`         The port of the host that will be controlled.
:bro:id:`Control::zone_id`: :bro:type:`string` :bro:attr:`&redef`         If :bro:id:`Control::host` is a non-global IPv6 address and
                                                                          requires a specific :rfc:`4007` ``zone_id``, it can be set here.
========================================================================= ================================================================

Constants
#########
=================================================== =================================================================
:bro:id:`Control::ignore_ids`: :bro:type:`set`      Variable IDs that are to be ignored by the update process.
:bro:id:`Control::topic_prefix`: :bro:type:`string` The topic prefix used for exchanging control messages via Broker.
=================================================== =================================================================

Events
######
=================================================================== ====================================================================
:bro:id:`Control::configuration_update`: :bro:type:`event`          This event is a wrapper and alias for the
                                                                    :bro:id:`Control::configuration_update_request` event.
:bro:id:`Control::configuration_update_request`: :bro:type:`event`  Inform the remote Bro instance that it's configuration may have been
                                                                    updated.
:bro:id:`Control::configuration_update_response`: :bro:type:`event` Message in response to a configuration update request.
:bro:id:`Control::id_value_request`: :bro:type:`event`              Event for requesting the value of an ID (a variable).
:bro:id:`Control::id_value_response`: :bro:type:`event`             Event for returning the value of an ID after an
                                                                    :bro:id:`Control::id_value_request` event.
:bro:id:`Control::net_stats_request`: :bro:type:`event`             Requests the current net_stats.
:bro:id:`Control::net_stats_response`: :bro:type:`event`            Returns the current net_stats.
:bro:id:`Control::peer_status_request`: :bro:type:`event`           Requests the current communication status.
:bro:id:`Control::peer_status_response`: :bro:type:`event`          Returns the current communication status.
:bro:id:`Control::shutdown_request`: :bro:type:`event`              Requests that the Bro instance begins shutting down.
:bro:id:`Control::shutdown_response`: :bro:type:`event`             Message in response to a shutdown request.
=================================================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Control::arg

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   This can be used by commands that take an argument.

.. bro:id:: Control::cmd

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   The command that is being done.  It's typically set on the
   command line.

.. bro:id:: Control::commands

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "shutdown",
         "id_value",
         "net_stats",
         "peer_status",
         "configuration_update"
      }

   The commands that can currently be given on the command line for
   remote control.

.. bro:id:: Control::controllee_listen

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Whether the controllee should call :bro:see:`Broker::listen`.
   In a cluster, this isn't needed since the setup process calls it.

.. bro:id:: Control::host

   :Type: :bro:type:`addr`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0.0.0.0``

   The address of the host that will be controlled.

.. bro:id:: Control::host_port

   :Type: :bro:type:`port`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0/tcp``

   The port of the host that will be controlled.

.. bro:id:: Control::zone_id

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   If :bro:id:`Control::host` is a non-global IPv6 address and
   requires a specific :rfc:`4007` ``zone_id``, it can be set here.

Constants
#########
.. bro:id:: Control::ignore_ids

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Default: ``{}``

   Variable IDs that are to be ignored by the update process.

.. bro:id:: Control::topic_prefix

   :Type: :bro:type:`string`
   :Default: ``"bro/control"``

   The topic prefix used for exchanging control messages via Broker.

Events
######
.. bro:id:: Control::configuration_update

   :Type: :bro:type:`event` ()

   This event is a wrapper and alias for the
   :bro:id:`Control::configuration_update_request` event.
   This event is also a primary hooking point for the control framework.

.. bro:id:: Control::configuration_update_request

   :Type: :bro:type:`event` ()

   Inform the remote Bro instance that it's configuration may have been
   updated.

.. bro:id:: Control::configuration_update_response

   :Type: :bro:type:`event` ()

   Message in response to a configuration update request.

.. bro:id:: Control::id_value_request

   :Type: :bro:type:`event` (id: :bro:type:`string`)

   Event for requesting the value of an ID (a variable).

.. bro:id:: Control::id_value_response

   :Type: :bro:type:`event` (id: :bro:type:`string`, val: :bro:type:`string`)

   Event for returning the value of an ID after an
   :bro:id:`Control::id_value_request` event.

.. bro:id:: Control::net_stats_request

   :Type: :bro:type:`event` ()

   Requests the current net_stats.

.. bro:id:: Control::net_stats_response

   :Type: :bro:type:`event` (s: :bro:type:`string`)

   Returns the current net_stats.

.. bro:id:: Control::peer_status_request

   :Type: :bro:type:`event` ()

   Requests the current communication status.

.. bro:id:: Control::peer_status_response

   :Type: :bro:type:`event` (s: :bro:type:`string`)

   Returns the current communication status.

.. bro:id:: Control::shutdown_request

   :Type: :bro:type:`event` ()

   Requests that the Bro instance begins shutting down.

.. bro:id:: Control::shutdown_response

   :Type: :bro:type:`event` ()

   Message in response to a shutdown request.


