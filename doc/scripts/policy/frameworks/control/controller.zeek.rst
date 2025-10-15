:tocdepth: 3

policy/frameworks/control/controller.zeek
=========================================
.. zeek:namespace:: Control

This is a utility script that implements the controller interface for the
control framework.  It's intended to be run to control a remote Zeek
and then shutdown.

It's intended to be used from the command line like this::

    zeek <scripts> frameworks/control/controller Control::host=<host_addr> Control::host_port=<host_port> Control::cmd=<command> [Control::arg=<arg>]

:Namespace: Control
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/control </scripts/base/frameworks/control/index>`

Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

