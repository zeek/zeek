:tocdepth: 3

policy/frameworks/management/controller/boot.zeek
=================================================

The cluster controller's boot logic runs in Zeek's supervisor and instructs
it to launch the Management controller process. The controller's main logic
resides in main.zeek, similarly to other frameworks. The new process will
execute that script.

If the current process is not the Zeek supervisor, this does nothing.

:Imports: :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`, :doc:`policy/frameworks/management/controller/config.zeek </scripts/policy/frameworks/management/controller/config.zeek>`

Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

