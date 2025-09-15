:orphan:

Package: policy/frameworks/management/agent
===========================================


:doc:`/scripts/policy/frameworks/management/agent/__load__.zeek`

   The entry point for the Management framework's cluster agent. It runs
   bootstrap logic for launching an agent process via Zeek's Supervisor.

:doc:`/scripts/policy/frameworks/management/agent/api.zeek`

   The event API of cluster agents. Most endpoints consist of event pairs,
   where the agent answers a request event with a corresponding response
   event. Such event pairs share the same name prefix and end in "_request" and
   "_response", respectively.

:doc:`/scripts/policy/frameworks/management/agent/boot.zeek`

   The cluster agent boot logic runs in Zeek's supervisor and instructs it to
   launch a Management agent process. The agent's main logic resides in main.zeek,
   similarly to other frameworks. The new process will execute that script.
   
   If the current process is not the Zeek supervisor, this does nothing.

:doc:`/scripts/policy/frameworks/management/agent/config.zeek`

   Configuration settings for a cluster agent.

:doc:`/scripts/policy/frameworks/management/agent/main.zeek`

   This is the main "runtime" of a cluster agent. Zeek does not load this
   directly; rather, the agent's bootstrapping module (in ./boot.zeek)
   specifies it as the script to run in the node newly created via Zeek's
   supervisor.

