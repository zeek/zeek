:tocdepth: 3

policy/frameworks/management/agent/boot.zeek
============================================

The cluster agent boot logic runs in Zeek's supervisor and instructs it to
launch a Management agent process. The agent's main logic resides in main.zeek,
similarly to other frameworks. The new process will execute that script.

If the current process is not the Zeek supervisor, this does nothing.

:Imports: :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`, :doc:`policy/frameworks/management/agent/config.zeek </scripts/policy/frameworks/management/agent/config.zeek>`

Summary
~~~~~~~
Redefinitions
#############
================================================================================== =
:zeek:id:`Broker::default_listen_address`: :zeek:type:`string` :zeek:attr:`&redef` 
:zeek:id:`SupervisorControl::enable_listen`: :zeek:type:`bool` :zeek:attr:`&redef` 
================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

