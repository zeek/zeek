:tocdepth: 3

policy/frameworks/management/agent/main.zeek
============================================
.. zeek:namespace:: Management::Agent::Runtime

This is the main "runtime" of a cluster agent. Zeek does not load this
directly; rather, the agent's bootstrapping module (in ./boot.zeek)
specifies it as the script to run in the node newly created via Zeek's
supervisor.

:Namespace: Management::Agent::Runtime
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`, :doc:`policy/frameworks/management </scripts/policy/frameworks/management/index>`, :doc:`policy/frameworks/management/agent/api.zeek </scripts/policy/frameworks/management/agent/api.zeek>`, :doc:`policy/frameworks/management/agent/config.zeek </scripts/policy/frameworks/management/agent/config.zeek>`, :doc:`policy/frameworks/management/node/api.zeek </scripts/policy/frameworks/management/node/api.zeek>`, :doc:`policy/frameworks/management/node/config.zeek </scripts/policy/frameworks/management/node/config.zeek>`, :doc:`policy/frameworks/management/supervisor/api.zeek </scripts/policy/frameworks/management/supervisor/api.zeek>`, :doc:`policy/frameworks/management/supervisor/config.zeek </scripts/policy/frameworks/management/supervisor/config.zeek>`

Summary
~~~~~~~
Types
#####
=============================================================================== ================================================================
:zeek:type:`Management::Agent::Runtime::DeployState`: :zeek:type:`record`       Request state for deploy requests.
:zeek:type:`Management::Agent::Runtime::NodeDispatchState`: :zeek:type:`record` Request state for node dispatches, tracking the requested action
                                                                                as well as received responses.
:zeek:type:`Management::Agent::Runtime::RestartState`: :zeek:type:`record`      Request state for restart requests, tracking received responses.
:zeek:type:`Management::Agent::Runtime::SupervisorState`: :zeek:type:`record`   Request state specific to the agent's Supervisor interactions.
=============================================================================== ================================================================

Redefinitions
#############
=========================================================================================== ==============================================================================================================
:zeek:type:`Management::Request::Request`: :zeek:type:`record`                              
                                                                                            
                                                                                            :New Fields: :zeek:type:`Management::Request::Request`
                                                                                            
                                                                                              supervisor_state_agent: :zeek:type:`Management::Agent::Runtime::SupervisorState` :zeek:attr:`&optional`
                                                                                            
                                                                                              deploy_state_agent: :zeek:type:`Management::Agent::Runtime::DeployState` :zeek:attr:`&optional`
                                                                                            
                                                                                              node_dispatch_state_agent: :zeek:type:`Management::Agent::Runtime::NodeDispatchState` :zeek:attr:`&optional`
                                                                                            
                                                                                              restart_state_agent: :zeek:type:`Management::Agent::Runtime::RestartState` :zeek:attr:`&optional`
:zeek:id:`Management::Request::timeout_interval`: :zeek:type:`interval` :zeek:attr:`&redef` 
:zeek:id:`Management::role`: :zeek:type:`Management::Role` :zeek:attr:`&redef`              
:zeek:id:`table_expire_interval`: :zeek:type:`interval` :zeek:attr:`&redef`                 
=========================================================================================== ==============================================================================================================

Events
######
=============================================================================== =
:zeek:id:`Management::Agent::Runtime::trigger_log_archival`: :zeek:type:`event` 
=============================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Management::Agent::Runtime::DeployState
   :source-code: policy/frameworks/management/agent/main.zeek 35 39

   :Type: :zeek:type:`record`

      nodes_pending: :zeek:type:`set` [:zeek:type:`string`]
         Zeek cluster nodes the provided configuration requested
         and which have not yet checked in with the agent.

   Request state for deploy requests.

.. zeek:type:: Management::Agent::Runtime::NodeDispatchState
   :source-code: policy/frameworks/management/agent/main.zeek 43 50

   :Type: :zeek:type:`record`

      action: :zeek:type:`vector` of :zeek:type:`string`
         The dispatched action. The first string is a command,
         any remaining strings its arguments.

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every node managed by this agent.

   Request state for node dispatches, tracking the requested action
   as well as received responses.

.. zeek:type:: Management::Agent::Runtime::RestartState
   :source-code: policy/frameworks/management/agent/main.zeek 53 57

   :Type: :zeek:type:`record`

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every node the agent asks the Supervisor
         to restart.

   Request state for restart requests, tracking received responses.

.. zeek:type:: Management::Agent::Runtime::SupervisorState
   :source-code: policy/frameworks/management/agent/main.zeek 25 32

   :Type: :zeek:type:`record`

      node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Name of the node the Supervisor is acting on, if applicable.

      status: :zeek:type:`Supervisor::Status` :zeek:attr:`&optional`
         The result of a status request.

      restart_result: :zeek:type:`bool` :zeek:attr:`&optional`
         The result of a restart request.

   Request state specific to the agent's Supervisor interactions.

Events
######
.. zeek:id:: Management::Agent::Runtime::trigger_log_archival
   :source-code: policy/frameworks/management/agent/main.zeek 217 261

   :Type: :zeek:type:`event` (run_archival: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`)



