:tocdepth: 3

base/frameworks/supervisor/control.zeek
=======================================
.. zeek:namespace:: SupervisorControl

The Zeek process supervision (remote) control API.  This defines a Broker topic
prefix and events that can be used to control an external Zeek supervisor process.
This API was introduced in Zeek 3.1.0 and considered unstable until 4.0.0.
That is, it may change in various incompatible ways without warning or
deprecation until the stable 4.0.0 release.

:Namespace: SupervisorControl
:Imports: :doc:`base/frameworks/supervisor/api.zeek </scripts/base/frameworks/supervisor/api.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
=================================================================================== =================================================================
:zeek:id:`SupervisorControl::topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef` The Broker topic prefix to use when subscribing to Supervisor API
                                                                                    requests and when publishing Supervisor API responses.
=================================================================================== =================================================================

Events
######
================================================================== ======================================================================
:zeek:id:`SupervisorControl::create_request`: :zeek:type:`event`   Send a request to a remote Supervisor process to create a node.
:zeek:id:`SupervisorControl::create_response`: :zeek:type:`event`  Handle a response from a Supervisor process that received
                                                                   :zeek:see:`SupervisorControl::create_request`.
:zeek:id:`SupervisorControl::destroy_request`: :zeek:type:`event`  Send a request to a remote Supervisor process to destroy a node.
:zeek:id:`SupervisorControl::destroy_response`: :zeek:type:`event` Handle a response from a Supervisor process that received
                                                                   :zeek:see:`SupervisorControl::destroy_request`.
:zeek:id:`SupervisorControl::restart_request`: :zeek:type:`event`  Send a request to a remote Supervisor process to restart a node.
:zeek:id:`SupervisorControl::restart_response`: :zeek:type:`event` Handle a response from a Supervisor process that received
                                                                   :zeek:see:`SupervisorControl::restart_request`.
:zeek:id:`SupervisorControl::status_request`: :zeek:type:`event`   Send a request to a remote Supervisor process to retrieve node status.
:zeek:id:`SupervisorControl::status_response`: :zeek:type:`event`  Handle a response from a Supervisor process that received
                                                                   :zeek:see:`SupervisorControl::status_request`.
:zeek:id:`SupervisorControl::stop_request`: :zeek:type:`event`     Send a request to a remote Supervisor to stop and shutdown its
                                                                   process tree.
================================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: SupervisorControl::topic_prefix

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/supervisor"``

   The Broker topic prefix to use when subscribing to Supervisor API
   requests and when publishing Supervisor API responses.  If you are
   publishing Supervisor requests, this is also the prefix string to use
   for their topic names.

Events
######
.. zeek:id:: SupervisorControl::create_request

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, node: :zeek:type:`Supervisor::NodeConfig`)

   Send a request to a remote Supervisor process to create a node.
   

   :reqid: an arbitrary string that will be directly echoed in the response
   

   :node: the desired configuration for the new supervised node process.

.. zeek:id:: SupervisorControl::create_response

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`string`)

   Handle a response from a Supervisor process that received
   :zeek:see:`SupervisorControl::create_request`.
   

   :reqid: an arbitrary string matching the value in the original request.
   

   :result: the return value of the remote call to
           :zeek:see:`Supervisor::create`.

.. zeek:id:: SupervisorControl::destroy_request

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, node: :zeek:type:`string`)

   Send a request to a remote Supervisor process to destroy a node.
   

   :reqid: an arbitrary string that will be directly echoed in the response
   

   :node: the name of the node to destory or empty string to mean "all
         nodes".

.. zeek:id:: SupervisorControl::destroy_response

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`bool`)

   Handle a response from a Supervisor process that received
   :zeek:see:`SupervisorControl::destroy_request`.
   

   :reqid: an arbitrary string matching the value in the original request.
   

   :result: the return value of the remote call to
           :zeek:see:`Supervisor::destroy`.

.. zeek:id:: SupervisorControl::restart_request

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, node: :zeek:type:`string`)

   Send a request to a remote Supervisor process to restart a node.
   

   :reqid: an arbitrary string that will be directly echoed in the response
   

   :node: the name of the node to restart or empty string to mean "all
         nodes".

.. zeek:id:: SupervisorControl::restart_response

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`bool`)

   Handle a response from a Supervisor process that received
   :zeek:see:`SupervisorControl::restart_request`.
   

   :reqid: an arbitrary string matching the value in the original request.
   

   :result: the return value of the remote call to
           :zeek:see:`Supervisor::restart`.

.. zeek:id:: SupervisorControl::status_request

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, node: :zeek:type:`string`)

   Send a request to a remote Supervisor process to retrieve node status.
   

   :reqid: an arbitrary string that will be directly echoed in the response
   

   :node: the name of the node to get status of or empty string to mean "all
         nodes".

.. zeek:id:: SupervisorControl::status_response

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`Supervisor::Status`)

   Handle a response from a Supervisor process that received
   :zeek:see:`SupervisorControl::status_request`.
   

   :reqid: an arbitrary string matching the value in the original request.
   

   :result: the return value of the remote call to
           :zeek:see:`Supervisor::status`.

.. zeek:id:: SupervisorControl::stop_request

   :Type: :zeek:type:`event` ()

   Send a request to a remote Supervisor to stop and shutdown its
   process tree.  There is no response to this message as the Supervisor
   simply terminates on receipt.


