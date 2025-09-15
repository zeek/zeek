:tocdepth: 3

policy/frameworks/management/__load__.zeek
==========================================

This loads Management framework functionality needed by both the controller
and agents. Note that there's no notion of loading "the Management
framework" -- one always loads "management/controller" or
"management/agent". This __load__ script exists only to simplify loading all
common functionality.

:Imports: :doc:`policy/frameworks/management/config.zeek </scripts/policy/frameworks/management/config.zeek>`, :doc:`policy/frameworks/management/log.zeek </scripts/policy/frameworks/management/log.zeek>`, :doc:`policy/frameworks/management/persistence.zeek </scripts/policy/frameworks/management/persistence.zeek>`, :doc:`policy/frameworks/management/request.zeek </scripts/policy/frameworks/management/request.zeek>`, :doc:`policy/frameworks/management/types.zeek </scripts/policy/frameworks/management/types.zeek>`, :doc:`policy/frameworks/management/util.zeek </scripts/policy/frameworks/management/util.zeek>`

Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

