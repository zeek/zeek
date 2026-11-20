:tocdepth: 3

base/misc/zip-analyzer-limit.zeek
=================================

When the ZIP analyzer hits a limit (and stops forwarding data to other analyzers), it triggers
an event. This script reacts to the event in order to trigger the weird and mark the connection
with an 'X'.


Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

