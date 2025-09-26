:orphan:

Package: policy/frameworks/management/controller
================================================


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

:doc:`/scripts/policy/frameworks/management/controller/main.zeek`

   This is the main "runtime" of the Management framework's controller. Zeek
   does not load this directly; rather, the controller's bootstrapping module
   (in ./boot.zeek) specifies it as the script to run in the node newly created
   by the supervisor.

