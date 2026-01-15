.. _event-semantics:

#################
 Event Semantics
#################

**************
 Event Groups
**************

Zeek supports enabling and disabling event and hook handlers at runtime
through event groups. While named event groups, hook handlers are
covered due to their structural similarity to event handlers as well.

Event and hook handlers can be part of multiple event groups. An event
or hook handler is disabled if any of the groups it's part of is
disabled. Conversely, event and hook handlers are enabled when all
groups they are part of are enabled. When Zeek starts, all event groups
are implicitly enabled. An event or hook handler that is not part of any
event group is always enabled.

Currently, two types of event groups exist: Attribute and module based.

Attribute Based Event Group
===========================

Attribute based event groups come into existence when an event or hook
handler has a :zeek:attr:`&group` attribute. The value of the group
attribute is a string identifying the group. There's a single global
namespace for attribute based event groups. Two event handlers in
different files or modules, but with the same group attribute value, are
part of the same group. Event and hook handlers can have more than one
group attributes.

.. literalinclude:: event_groups_attr_01.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

This example shows ``http_request``, ``http_header`` and ``http_reply``
event handlers, all with a group attribute of ``http-print-debugging``.
When running Zeek against a pcap containing a single HTTP transaction,
the output is as follows.

.. code:: console

   $ zeek -r traces/get.trace  ./event_groups_attr_01.zeek
   HTTP request: GET /download/CHANGES.bro-aux.txt (141.142.228.5->192.150.187.43)
   HTTP header : User-Agent=Wget/1.14 (darwin12.2.0) (141.142.228.5->192.150.187.43)
   HTTP reply: 200/OK version 1.1 (192.150.187.43->141.142.228.5)
   HTTP header : Server=Apache/2.4.3 (Fedora) (192.150.187.43->141.142.228.5)

Such debugging functionality would generally only be enabled on demand.
Extending the above script, we introduce an option and a change handler
function from the :ref:`configuration framework <framework-configuration>`
to enable and disable the ``http-print-debugging`` event group at runtime.

.. literalinclude:: event_groups_attr_02.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

Whenever the option ``Debug::http_print_debugging`` is set to ``T``,
:zeek:see:`enable_event_group` is invoked to ensure the
``http-print-debugging`` group is enabled. Conversely, when the option
is set to ``F``, :zeek:see:`disable_event_group` disables all event
handlers in the group ``http-print-debugging``.

The very same behavior can be achieved by testing the
``Debug::http_print_debugging`` option within the respective event
handlers using and ``if`` statement and early return. In contrast, event
groups work in a more declarative way. Further, when disabling event
handlers via event groups, their implementation is never invoked and is
therefore a more performant way to short-circuit execution.

Module Based Event Group
========================

Besides attribute based event groups, Zeek supports implicit module
based event groups. Event and hook handlers are part of an event group
that represents the module in which they were implemented. The builtin
functions :zeek:see:`disable_module_events` and
:zeek:see:`enable_module_events` can be used to disable and enable
all event and hook handlers within modules.

An interesting idea here is to implement enabling and disabling of Zeek
packages at runtime. For example, the `CommunityID
<https://github.com/corelight/zeek-community-id>`_ package implements
its functionality in the ``CommunityID`` and ``CommunityID::Notice``
modules. The `JA3 <https://github.com/salesforce/ja3>`_ package
implements its event handlers in the ``JA3`` and ``JA3_Server`` modules.

.. literalinclude:: event_groups_module_01.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

The above script implements toggling of Zeek package functionality at
runtime via the options ``Packages::ja3_enabled`` and
``Packages::community_id_enabled``. While for most packages and
deployments a Zeek restart is an acceptable way to disable or enable a
package - generally this isn't a regular operation - module based event
groups provide a powerful primitive to support runtime toggling of
scripting functionality.

.. note::

   A caveat around the above example: The JA3 package builds up state
   based on the :zeek:see:`ssl_extension` events from SSL ClientHello
   and ServerHello messages. When the JA3 event handlers are enabled
   right during processing of these events, the resulting JA3 hash might
   be based on a partial list of extensions only.

   While all :zeek:see:`ssl_extension` handlers are processed jointly
   for each instance of the event, generally state build up and dynamic
   enabling and disabling may need careful consideration.

.. _tracing_events:

**************
Tracing Events
**************

Zeek provides a mechanism for recording the events that occur during
an execution run (on live traffic, or from a pcap) in a manner that you
can then later replay to get the same effect but without the traffic source.
You can also edit the recording to introduce differences between the original,
such as introducing corner-cases to aid in testing, or anonymizing sensitive
information.

You create a trace using:

.. code-block:: console

  zeek --event-trace=mytrace.zeek <traffic-option> <other-options> <scripts...>

or, equivalently:

.. code-block:: console

  zeek -E mytrace.zeek <traffic-option> <other-options> <scripts...>

Here, the *traffic-option* would be ``-i`` or ``-r`` to arrange for
a source of network traffic.  The trace will be written to the file
``mytrace.zeek`` which, as the extension suggests, is itself a Zeek script.
You can then replay the events using:

.. code-block:: console

  zeek <other-options> <scripts...> mytrace.zeek

One use case for event-tracing is to turn a sensitive PCAP that can't
be shared into a reflection of that same activity that - with some editing, for
example to change IP addresses - is safe to share.  To facilitate such
editing, the generated script includes at the end a summary of all of
the constants present in the script that might be sensitive and require
editing (such as addresses and strings), to make it easier to know what
to search for and edit in the script.  The generated script also includes
a global ``__base_time`` that's used to make it easy to alter (most of)
the times in the trace without altering their relative offsets.

The generated script aims to ensure that event values that were related
during the original run stay related when replayed; re-execution should
proceed in a manner identical to how it did originally.  There are however
several considerations:

* Zeek is unable to accurately trace events that include values that cannot
  be faithfully recreated in a Zeek script, namely those having types of
  ``opaque``, ``file``, or ``any``.  Upon encountering these, it generates
  variables reflecting their unsupported nature, such as ``global
  __UNSUPPORTED21: opaque of x509;``, and initializes them with code like
  ``__UNSUPPORTED21 = UNSUPPORTED opaque of x509;``.  The generated script
  is meant to produce syntax errors if run directly, and the names make
  it easy to search for the elements that need to somehow be addressed.

* Zeek only traces events that reflect traffic processing, i.e., those
  occurring after :zeek:id:`network_time` is set.  Even if you don't include
  a network traffic source, it skips the :zeek:id:`zeek_init` event
  (since it is always automatically generated).

* The trace does *not* include events generated by scripts, only those
  generated by the "event engine".

* The trace is generated upon Zeek cleanly exiting, so if Zeek crashes,
  no trace will be produced. Stopping Zeek via *ctrl-c* does trigger a
  clean exit.

* A subtle issue arises regarding any changes that the scripts in the
  original execution made to values present in subsequent events.  If
  you re-run using the event trace script as well as those scripts,
  the changes the scripts make during the re-run will be discarded and
  instead replaced with the changes made during the original execution.
  This generally won't matter if you're using the exact same scripts for
  replay as originally, but if you've made changes to those scripts, then
  it could.  If you need the replay script to "respond" to changes made
  during the re-execution, you can delete from the replay script every
  line marked with the comment ``# from script``.

.. note::

  It's possible that some timers will behave differently upon replay
  than originally.  If you encounter this and it creates a problem, we
  would be interested to hear about it so we can consider whether the
  problem can be remedied.
