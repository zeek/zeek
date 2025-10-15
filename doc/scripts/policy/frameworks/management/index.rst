:orphan:

Package: policy/frameworks/management
=====================================


:doc:`/scripts/policy/frameworks/management/agent/__load__.zeek`

   The entry point for the Management framework's cluster agent. It runs
   bootstrap logic for launching an agent process via Zeek's Supervisor.

:doc:`/scripts/policy/frameworks/management/agent/api.zeek`

   The event API of cluster agents. Most endpoints consist of event pairs,
   where the agent answers a request event with a corresponding response
   event. Such event pairs share the same name prefix and end in "_request" and
   "_response", respectively.

:doc:`/scripts/policy/frameworks/management/types.zeek`

   This module holds the basic types needed for the Management framework. These
   are used by both cluster agent and controller, and several have corresponding
   implementations in zeek-client.

:doc:`/scripts/policy/frameworks/management/agent/boot.zeek`

   The cluster agent boot logic runs in Zeek's supervisor and instructs it to
   launch a Management agent process. The agent's main logic resides in main.zeek,
   similarly to other frameworks. The new process will execute that script.
   
   If the current process is not the Zeek supervisor, this does nothing.

:doc:`/scripts/policy/frameworks/management/agent/config.zeek`

   Configuration settings for a cluster agent.

:doc:`/scripts/policy/frameworks/management/__load__.zeek`

   This loads Management framework functionality needed by both the controller
   and agents. Note that there's no notion of loading "the Management
   framework" -- one always loads "management/controller" or
   "management/agent". This __load__ script exists only to simplify loading all
   common functionality.

:doc:`/scripts/policy/frameworks/management/config.zeek`

   Management framework configuration settings common to agent and controller.
   This does not include config settings that exist in both agent and
   controller but that they set differently, since setting defaults here would
   be awkward or pointless (since both node types would overwrite them
   anyway). For role-specific settings, see management/controller/config.zeek
   and management/agent/config.zeek.

:doc:`/scripts/policy/frameworks/management/log.zeek`

   This module implements logging abilities for controller and agent. It uses
   Zeek's logging framework and works only for nodes managed by the
   supervisor. In this setting Zeek's logging framework operates locally, i.e.,
   this does not involve logger nodes.

:doc:`/scripts/policy/frameworks/management/persistence.zeek`

   Common adjustments for any kind of Zeek node when we run the Management
   framework.

:doc:`/scripts/policy/frameworks/management/request.zeek`

   This module implements a request state abstraction in the Management
   framework that both controller and agent use to connect request events to
   subsequent response ones, and to be able to time out such requests.

:doc:`/scripts/policy/frameworks/management/util.zeek`

   Utility functions for the Management framework, available to agent
   and controller.

:doc:`/scripts/policy/frameworks/management/controller/config.zeek`

   Configuration settings for the cluster controller.

:doc:`/scripts/policy/frameworks/management/controller/__load__.zeek`

   The entry point for the Management framework's cluster controller. It runs
   bootstrap logic for launching a controller process via Zeek's Supervisor.

:doc:`/scripts/policy/frameworks/management/controller/api.zeek`

   The event API of cluster controllers. Most endpoints consist of event pairs,
   where the controller answers the client's request event with a corresponding
   response event. Such event pairs share the same name prefix and end in
   "_request" and "_response", respectively.

:doc:`/scripts/policy/frameworks/management/controller/boot.zeek`

   The cluster controller's boot logic runs in Zeek's supervisor and instructs
   it to launch the Management controller process. The controller's main logic
   resides in main.zeek, similarly to other frameworks. The new process will
   execute that script.
   
   If the current process is not the Zeek supervisor, this does nothing.

:doc:`/scripts/policy/frameworks/management/node/api.zeek`

   The Management event API of cluster nodes. The API consists of request/
   response event pairs, like elsewhere in the Management, Supervisor, and
   Control frameworks.

:doc:`/scripts/policy/frameworks/management/node/config.zeek`

   Configuration settings for nodes controlled by the Management framework.

:doc:`/scripts/policy/frameworks/management/supervisor/__load__.zeek`


:doc:`/scripts/policy/frameworks/management/supervisor/main.zeek`

   This module provides functionality the Management framework places directly
   in the Supervisor.

:doc:`/scripts/policy/frameworks/management/supervisor/api.zeek`


:doc:`/scripts/policy/frameworks/management/supervisor/config.zeek`

   Configuration settings for the Management framework's supervisor extension.

:doc:`/scripts/policy/frameworks/management/agent/main.zeek`

   This is the main "runtime" of a cluster agent. Zeek does not load this
   directly; rather, the agent's bootstrapping module (in ./boot.zeek)
   specifies it as the script to run in the node newly created via Zeek's
   supervisor.

:doc:`/scripts/policy/frameworks/management/controller/main.zeek`

   This is the main "runtime" of the Management framework's controller. Zeek
   does not load this directly; rather, the controller's bootstrapping module
   (in ./boot.zeek) specifies it as the script to run in the node newly created
   by the supervisor.

:doc:`/scripts/policy/frameworks/management/node/__load__.zeek`


:doc:`/scripts/policy/frameworks/management/node/main.zeek`

   This module provides Management framework functionality present in every
   cluster node, to allowing Management agents to interact with the nodes.

