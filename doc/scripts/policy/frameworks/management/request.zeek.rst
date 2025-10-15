:tocdepth: 3

policy/frameworks/management/request.zeek
=========================================
.. zeek:namespace:: Management::Request

This module implements a request state abstraction in the Management
framework that both controller and agent use to connect request events to
subsequent response ones, and to be able to time out such requests.

:Namespace: Management::Request
:Imports: :doc:`policy/frameworks/management/config.zeek </scripts/policy/frameworks/management/config.zeek>`, :doc:`policy/frameworks/management/types.zeek </scripts/policy/frameworks/management/types.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
=========================================================================================== =======================================
:zeek:id:`Management::Request::timeout_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The timeout interval for request state.
=========================================================================================== =======================================

State Variables
###############
=================================================================================== ==========================================================
:zeek:id:`Management::Request::null_req`: :zeek:type:`Management::Request::Request` A token request that serves as a null/nonexistent request.
=================================================================================== ==========================================================

Types
#####
============================================================== ====================================================================
:zeek:type:`Management::Request::Request`: :zeek:type:`record` Request records track state associated with a request/response event
                                                               pair.
============================================================== ====================================================================

Redefinitions
#############
============================================================== ===========================================================================================================================
:zeek:type:`Management::Request::Request`: :zeek:type:`record` 
                                                               
                                                               :New Fields: :zeek:type:`Management::Request::Request`
                                                               
                                                                 finish: :zeek:type:`function` (req: :zeek:type:`Management::Request::Request`) : :zeek:type:`void` :zeek:attr:`&optional`
                                                                   A callback to invoke when this request is finished via
                                                                   :zeek:see:`Management::Request::finish`.
============================================================== ===========================================================================================================================

Events
######
=================================================================== ======================================================================
:zeek:id:`Management::Request::request_expired`: :zeek:type:`event` This event fires when a request times out (as per the
                                                                    Management::Request::timeout_interval) before it has been finished via
                                                                    Management::Request::finish().
=================================================================== ======================================================================

Functions
#########
================================================================ ========================================================================
:zeek:id:`Management::Request::create`: :zeek:type:`function`    This function establishes request state.
:zeek:id:`Management::Request::finish`: :zeek:type:`function`    This function marks a request as complete and causes Zeek to release
                                                                 its internal state.
:zeek:id:`Management::Request::is_null`: :zeek:type:`function`   This function is a helper predicate to indicate whether a given
                                                                 request is null.
:zeek:id:`Management::Request::lookup`: :zeek:type:`function`    This function looks up the request for a given request ID and returns
                                                                 it.
:zeek:id:`Management::Request::to_string`: :zeek:type:`function` For troubleshooting, this function renders a request record to a string.
================================================================ ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Management::Request::timeout_interval
   :source-code: policy/frameworks/management/request.zeek 52 52

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``
   :Redefinition: from :doc:`/scripts/policy/frameworks/management/agent/main.zeek`

      ``=``::

         5.0 secs


   The timeout interval for request state. Such state (see the
   :zeek:see:`Management::Request` module) ties together request and
   response event pairs. A timeout causes cleanup of request state if
   regular request/response processing hasn't already done so. It
   applies both to request state kept in the controller and the agent,
   though the two use different timeout values: agent-side requests time
   out more quickly. This allows agents to send more meaningful error
   messages, while the controller's timeouts serve as a last resort to
   ensure response to the client.

State Variables
###############
.. zeek:id:: Management::Request::null_req
   :source-code: policy/frameworks/management/request.zeek 55 55

   :Type: :zeek:type:`Management::Request::Request`
   :Default:

      ::

         {
            id=""
            parent_id=<uninitialized>
            results=[]
            finished=T
            finish=<uninitialized>
            supervisor_state_agent=<uninitialized>
            deploy_state_agent=<uninitialized>
            node_dispatch_state_agent=<uninitialized>
            restart_state_agent=<uninitialized>
            deploy_state=<uninitialized>
            get_nodes_state=<uninitialized>
            node_dispatch_state=<uninitialized>
            restart_state=<uninitialized>
            test_state=<uninitialized>
         }


   A token request that serves as a null/nonexistent request.

Types
#####
.. zeek:type:: Management::Request::Request
   :source-code: policy/frameworks/management/request.zeek 17 33

   :Type: :zeek:type:`record`

      id: :zeek:type:`string`
         Each request has a hopefully unique ID provided by the requester.

      parent_id: :zeek:type:`string` :zeek:attr:`&optional`
         For requests that result based upon another request (such as when
         the controller sends requests to agents based on a request it
         received by the client), this specifies that original, "parent"
         request.

      results: :zeek:type:`Management::ResultVec` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         The results vector builds up the list of results we eventually
         send to the requestor when we have processed the request.

      finished: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         An internal flag to track whether a request is complete.

      finish: :zeek:type:`function` (<recursion>) : :zeek:type:`void` :zeek:attr:`&optional`
         A callback to invoke when this request is finished via
         :zeek:see:`Management::Request::finish`.

      supervisor_state_agent: :zeek:type:`Management::Agent::Runtime::SupervisorState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/management/agent/main.zeek` is loaded)


      deploy_state_agent: :zeek:type:`Management::Agent::Runtime::DeployState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/management/agent/main.zeek` is loaded)


      node_dispatch_state_agent: :zeek:type:`Management::Agent::Runtime::NodeDispatchState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/management/agent/main.zeek` is loaded)


      restart_state_agent: :zeek:type:`Management::Agent::Runtime::RestartState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/management/agent/main.zeek` is loaded)


      deploy_state: :zeek:type:`Management::Controller::Runtime::DeployState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/management/controller/main.zeek` is loaded)


      get_nodes_state: :zeek:type:`Management::Controller::Runtime::GetNodesState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/management/controller/main.zeek` is loaded)


      node_dispatch_state: :zeek:type:`Management::Controller::Runtime::NodeDispatchState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/management/controller/main.zeek` is loaded)


      restart_state: :zeek:type:`Management::Controller::Runtime::RestartState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/management/controller/main.zeek` is loaded)


      test_state: :zeek:type:`Management::Controller::Runtime::TestState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/management/controller/main.zeek` is loaded)


   Request records track state associated with a request/response event
   pair. Calls to
   :zeek:see:`Management::Request::create` establish such state
   when an entity sends off a request event, while
   :zeek:see:`Management::Request::finish` clears the state when
   a corresponding response event comes in, or the state times out.

Events
######
.. zeek:id:: Management::Request::request_expired
   :source-code: policy/frameworks/management/request.zeek 84 84

   :Type: :zeek:type:`event` (req: :zeek:type:`Management::Request::Request`)

   This event fires when a request times out (as per the
   Management::Request::timeout_interval) before it has been finished via
   Management::Request::finish().
   

   :param req: the request state that is expiring.
   

Functions
#########
.. zeek:id:: Management::Request::create
   :source-code: policy/frameworks/management/request.zeek 119 124

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string` :zeek:attr:`&default` = ``fD0qxAnfwOe`` :zeek:attr:`&optional`) : :zeek:type:`Management::Request::Request`

   This function establishes request state.
   

   :param reqid: the identifier to use for the request.
   

.. zeek:id:: Management::Request::finish
   :source-code: policy/frameworks/management/request.zeek 134 148

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string`) : :zeek:type:`bool`

   This function marks a request as complete and causes Zeek to release
   its internal state. When the request does not exist, this does
   nothing.
   

   :param reqid: the ID of the request state to release.
   

.. zeek:id:: Management::Request::is_null
   :source-code: policy/frameworks/management/request.zeek 150 156

   :Type: :zeek:type:`function` (request: :zeek:type:`Management::Request::Request`) : :zeek:type:`bool`

   This function is a helper predicate to indicate whether a given
   request is null.
   

   :param request: a Request record to check.
   

   :returns: T if the given request matches the null_req instance, F otherwise.
   

.. zeek:id:: Management::Request::lookup
   :source-code: policy/frameworks/management/request.zeek 126 132

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string`) : :zeek:type:`Management::Request::Request`

   This function looks up the request for a given request ID and returns
   it. When no such request exists, returns Management::Request::null_req.
   

   :param reqid: the ID of the request state to retrieve.
   

.. zeek:id:: Management::Request::to_string
   :source-code: policy/frameworks/management/request.zeek 158 168

   :Type: :zeek:type:`function` (request: :zeek:type:`Management::Request::Request`) : :zeek:type:`string`

   For troubleshooting, this function renders a request record to a string.
   

   :param request: the request to render.
   


