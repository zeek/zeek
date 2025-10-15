:tocdepth: 3

policy/frameworks/management/controller/main.zeek
=================================================
.. zeek:namespace:: Management::Controller::Runtime

This is the main "runtime" of the Management framework's controller. Zeek
does not load this directly; rather, the controller's bootstrapping module
(in ./boot.zeek) specifies it as the script to run in the node newly created
by the supervisor.

:Namespace: Management::Controller::Runtime
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`policy/frameworks/management </scripts/policy/frameworks/management/index>`, :doc:`policy/frameworks/management/agent/api.zeek </scripts/policy/frameworks/management/agent/api.zeek>`, :doc:`policy/frameworks/management/agent/config.zeek </scripts/policy/frameworks/management/agent/config.zeek>`, :doc:`policy/frameworks/management/controller/api.zeek </scripts/policy/frameworks/management/controller/api.zeek>`, :doc:`policy/frameworks/management/controller/config.zeek </scripts/policy/frameworks/management/controller/config.zeek>`

Summary
~~~~~~~
Types
#####
==================================================================================== ====================================================================
:zeek:type:`Management::Controller::Runtime::ConfigState`: :zeek:type:`enum`         A cluster configuration uploaded by the client goes through multiple
                                                                                     states on its way to deployment.
:zeek:type:`Management::Controller::Runtime::DeployState`: :zeek:type:`record`       Request state specific to
                                                                                     :zeek:see:`Management::Controller::API::deploy_request` and
                                                                                     :zeek:see:`Management::Controller::API::deploy_response`.
:zeek:type:`Management::Controller::Runtime::GetNodesState`: :zeek:type:`record`     Request state specific to
                                                                                     :zeek:see:`Management::Controller::API::get_nodes_request` and
                                                                                     :zeek:see:`Management::Controller::API::get_nodes_response`.
:zeek:type:`Management::Controller::Runtime::NodeDispatchState`: :zeek:type:`record` Request state for node dispatch requests, to track the requested
                                                                                     action and received responses.
:zeek:type:`Management::Controller::Runtime::RestartState`: :zeek:type:`record`      Request state specific to
                                                                                     :zeek:see:`Management::Controller::API::restart_request` and
                                                                                     :zeek:see:`Management::Controller::API::restart_response`.
:zeek:type:`Management::Controller::Runtime::TestState`: :zeek:type:`record`         Dummy state for internal state-keeping test cases.
==================================================================================== ====================================================================

Redefinitions
#############
============================================================================== =============================================================================================================
:zeek:type:`Management::Request::Request`: :zeek:type:`record`                 
                                                                               
                                                                               :New Fields: :zeek:type:`Management::Request::Request`
                                                                               
                                                                                 deploy_state: :zeek:type:`Management::Controller::Runtime::DeployState` :zeek:attr:`&optional`
                                                                               
                                                                                 get_nodes_state: :zeek:type:`Management::Controller::Runtime::GetNodesState` :zeek:attr:`&optional`
                                                                               
                                                                                 node_dispatch_state: :zeek:type:`Management::Controller::Runtime::NodeDispatchState` :zeek:attr:`&optional`
                                                                               
                                                                                 restart_state: :zeek:type:`Management::Controller::Runtime::RestartState` :zeek:attr:`&optional`
                                                                               
                                                                                 test_state: :zeek:type:`Management::Controller::Runtime::TestState` :zeek:attr:`&optional`
:zeek:id:`Management::role`: :zeek:type:`Management::Role` :zeek:attr:`&redef` 
:zeek:id:`table_expire_interval`: :zeek:type:`interval` :zeek:attr:`&redef`    
============================================================================== =============================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Management::Controller::Runtime::ConfigState
   :source-code: policy/frameworks/management/controller/main.zeek 23 28

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Management::Controller::Runtime::STAGED Management::Controller::Runtime::ConfigState

         As provided by the client.

      .. zeek:enum:: Management::Controller::Runtime::READY Management::Controller::Runtime::ConfigState

         Necessary updates made, e.g. ports filled in.

      .. zeek:enum:: Management::Controller::Runtime::DEPLOYED Management::Controller::Runtime::ConfigState

         Sent off to the agents for deployment.

   A cluster configuration uploaded by the client goes through multiple
   states on its way to deployment.

.. zeek:type:: Management::Controller::Runtime::DeployState
   :source-code: policy/frameworks/management/controller/main.zeek 32 40

   :Type: :zeek:type:`record`

      config: :zeek:type:`Management::Configuration`
         The cluster configuration the controller is deploying.

      is_internal: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Whether this is a controller-internal deployment, or
         triggered via a request by a remote peer/client.

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every controller/agent transaction.

   Request state specific to
   :zeek:see:`Management::Controller::API::deploy_request` and
   :zeek:see:`Management::Controller::API::deploy_response`.

.. zeek:type:: Management::Controller::Runtime::GetNodesState
   :source-code: policy/frameworks/management/controller/main.zeek 45 48

   :Type: :zeek:type:`record`

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every controller/agent transaction.

   Request state specific to
   :zeek:see:`Management::Controller::API::get_nodes_request` and
   :zeek:see:`Management::Controller::API::get_nodes_response`.

.. zeek:type:: Management::Controller::Runtime::NodeDispatchState
   :source-code: policy/frameworks/management/controller/main.zeek 61 71

   :Type: :zeek:type:`record`

      action: :zeek:type:`vector` of :zeek:type:`string`
         The dispatched action. The first string is a command,
         any remaining strings its arguments.

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every controller/agent transaction.
         The set of strings tracks the node names from which
         we still expect responses, before we can respond back
         to the client.

   Request state for node dispatch requests, to track the requested
   action and received responses. Node dispatches are requests to
   execute pre-implemented actions on every node in the cluster,
   and report their outcomes. See
   :zeek:see:`Management::Agent::API::node_dispatch_request` and
   :zeek:see:`Management::Agent::API::node_dispatch_response` for the
   agent/controller interaction, and
   :zeek:see:`Management::Controller::API::get_id_value_request` and
   :zeek:see:`Management::Controller::API::get_id_value_response`
   for an example of a specific API the controller generalizes into
   a dispatch.

.. zeek:type:: Management::Controller::Runtime::RestartState
   :source-code: policy/frameworks/management/controller/main.zeek 76 79

   :Type: :zeek:type:`record`

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every controller/agent transaction.

   Request state specific to
   :zeek:see:`Management::Controller::API::restart_request` and
   :zeek:see:`Management::Controller::API::restart_response`.

.. zeek:type:: Management::Controller::Runtime::TestState
   :source-code: policy/frameworks/management/controller/main.zeek 82 83

   :Type: :zeek:type:`record`

   Dummy state for internal state-keeping test cases.


