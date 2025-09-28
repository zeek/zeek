:tocdepth: 3

policy/frameworks/control/controllee.zeek
=========================================
.. zeek:namespace:: Control

The controllee portion of the control framework.  Load this script if remote
runtime control of the Zeek process is desired.

A controllee only needs to load the controllee script in addition
to the specific analysis scripts desired.  It may also need a node
configured as a controller node in the communications nodes configuration::

    zeek <scripts> frameworks/control/controllee

:Namespace: Control
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/control </scripts/base/frameworks/control/index>`

Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

