
.. _script-event-groups:

============
Event Groups
============

Zeek supports enabling and disabling event and hook handlers at runtime
through event groups. While named event groups, hook handlers are covered
due to their structural similarity to event handlers as well.

Event and hook handlers can be part of multiple event groups. An event or
hook handler is disabled if any of the groups it's part of is disabled.
Conversely, event and hook handlers are enabled when all groups they
are part of are enabled. When Zeek starts, all event groups are implicitly
enabled. An event or hook handler that is not part of any event group is
always enabled.

Currently, two types of event groups exist: Attribute and module based.


Attribute Based Event Group
===========================

Attribute based event groups come into existence when an event or hook
handler has a :zeek:attr:`&group` attribute. The value of the group
attribute is a string identifying the group. There's a single global namespace
for attribute based event groups. Two event handlers in different files
or modules, but with the same group attribute value, are part of the same group.
Event and hook handlers can have more than one group attributes.

.. literalinclude:: event_groups_attr_01.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

This example shows ``http_request``, ``http_header`` and ``http_reply`` event
handlers, all with a group attribute of ``http-print-debugging``.
When running Zeek against a pcap containing a single HTTP transaction,
the output is as follows.

.. code-block:: console

   $ zeek -r traces/get.trace  ./event_groups_attr_01.zeek
   HTTP request: GET /download/CHANGES.bro-aux.txt (141.142.228.5->192.150.187.43)
   HTTP header : User-Agent=Wget/1.14 (darwin12.2.0) (141.142.228.5->192.150.187.43)
   HTTP reply: 200/OK version 1.1 (192.150.187.43->141.142.228.5)
   HTTP header : Server=Apache/2.4.3 (Fedora) (192.150.187.43->141.142.228.5)

Such debugging functionality would generally only be enabled on demand. Extending
the above script, we introduce an option and a change handler function from the
:ref:`configuration framework`<framework-configuration>`
to enable and disable the ``http-print-debugging`` event group at runtime.

.. literalinclude:: event_groups_attr_02.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

Whenever the option ``Debug::http_print_debugging`` is set to ``T``,
:zeek:see:`enable_event_group` is invoked to ensure the ``http-print-debugging``
group is enabled. Conversely, when the option is set to ``F``,
:zeek:see:`disable_event_group` disables all event handlers in the group
``http-print-debugging``.


The very same behavior can be achieved by testing the ``Debug::http_print_debugging``
option within the respective event handlers using and ``if`` statement and
early return. In contrast, event groups work in a more declarative way.
Further, when disabling event handlers via event groups, their implementation
is never invoked and is therefore a more performant way to short-circuit
execution.


Module Based Event Group
========================

Besides attribute based event groups, Zeek supports implicit module based
event groups. Event and hook handlers are part of an event group that
represents the module in which they were implemented. The builtin functions
:zeek:see:`disable_module_events` and :zeek:see:`enable_module_events` can
be used to disable and enable all event and hook handlers within modules.

An interesting idea here is to implement enabling and disabling of Zeek packages
at runtime. For example, the `CommunityID <https://github.com/corelight/zeek-community-id>`_
package implements its functionality in the ``CommunityID`` and
``CommunityID::Notice`` modules. The `JA3 <https://github.com/salesforce/ja3>`_
package implements its event handlers in the ``JA3`` and ``JA3_Server`` modules.

.. literalinclude:: event_groups_module_01.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

The above script implements toggling of Zeek package functionality at
runtime via the options ``Packages::ja3_enabled`` and ``Packages::community_id_enabled``.
While for most packages and deployments a Zeek restart is an acceptable
way to disable or enable a package - generally this isn't a regular operation -
module based event groups provide a powerful primitive to support runtime
toggling of scripting functionality.

.. note::

   A caveat around the above example: The JA3 package builds up state based
   on the :zeek:see:`ssl_extension` events from SSL ClientHello and ServerHello
   messages. When the JA3 event handlers are enabled right during processing
   of these events, the resulting JA3 hash might be based on a partial list
   of extensions only.

   While all :zeek:see:`ssl_extension` handlers are processed jointly
   for each instance of the event, generally state build up and
   dynamic enabling and disabling may need careful consideration.
