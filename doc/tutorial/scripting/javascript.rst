.. _javascript:

==========
JavaScript
==========

.. versionadded:: 6.0

.. note::

   Link to external `ZeekJS documentation`_.


.. note::

   The JavaScript integration does not provide Zeek's typical backwards
   compatibility guarantees at this point. The plugin itself is at semantic
   version 0.9.1 at the time of writing meaning the API is not stable.
   That said, we'll avoid unnecessary breakage.


Preamble
========

In the scope of integrating with external systems, Zeek can be extended by
:ref:`implementing C++ plugins <writing-plugins>` or using the :zeek:see:`system`
function to call external programs from Zeek scripts. The :ref:`framework-input`
can be leveraged for data ingestion (with :ref:`raw reader <input-raw-reader>`
reader providing flexibility to consume input from external programs as events).
The :ref:`broker-framework` is popular for exchanging events between
Zeek and an external program using WebSockets.
The external program sometimes solely acts as a proxy between Zeek and another
external system.

JavaScript integration adds to the above by enabling Zeek to load JavaScript
code directly, thereby allowing developers to use its rich ecosystem of
built-in and third-party libraries directly within Zeek.

If you previously wanted to start a `HTTP server`_ within Zeek, record Zeek
event data on-the-fly to a `Redis`_ database, got scared at looking at
:zeek:see:`ActiveHTTP`'s implementation (or annoyed that it eats all newlines
in HTTP responses), you may want to give JavaScript a go!

Built-in Plugin
===============

The external `ZeekJS`_ plugin is included with Zeek as an optional built-in plugin.
When `Node.js`_ development headers and libraries are found when building Zeek
from source, the plugin is automatically included.

If Node.js is installed in a non-standard location, ``-D NODEJS_ROOT_DIR`` has
to be provided to ``./configure``.
Assuming an installation of Node.js in ``/opt/node-19.8``, the command to
use is as follows. Discovered headers and libraries will be reported in the
output.
On Linux distributions providing Node.js development packages
(Ubuntu 22.10, Fedora, Debian bookworm) the extra ``-D NODEJS_ROOT_DIR``
is not required.

.. code-block:: console

   $ ./configure -D NODEJS_ROOT_DIR:string=/opt/node-19.8
   ...
   -- Looking for __system_property_get
   -- Looking for __system_property_get - not found
   -- Found Nodejs: /opt/node-19.8/include (found version "19.8.1")
   --      version: 19.8.1
   --    libraries: /opt/node-19.8/lib/libnode.so.111
   --         uv.h: /opt/node-19.8/include/node
   --   v8config.h: /opt/node-19.8/include/node
   --   Building in plugin: zeekjs (/home/user/zeek/auxil/zeekjs)
   ...
   $ make -j
   ...
   $ sudo make install

To test if the plugin is available on a given Zeek installation, run ``zeek -N Zeek::JavaScript``.
The ``zeek`` executable will also be dynamically linked against ``libnode.so``.

.. code-block:: console

   $ zeek -NN Zeek::JavaScript
   Zeek::JavaScript - Experimental JavaScript support for Zeek (built-in)
       Implements LoadFile (priority 0)

   $ ldd $(which zeek) | grep libnode
           libnode.so.111 => /opt/node-19.8/lib/libnode.so.111 (0x00007f281aa25000)

The main hooking mechanism used by the plugin is loading files with ``.js`` and ``.cjs`` suffixes.

If no such files are provided on the command-line or via ``@load``, neither
the Node.js environment nor the V8 JavaScript engine will be initialized and there
will be no runtime overhead of having the plugin available. When JavaScript
code is loaded, additional overhead may come from processing JavaScript's IO
loop or running garbage collection.


Hello World
===========

When JavaScript is executed by Zeek, a ``zeek`` object is added to
the JavaScript's global namespace.
This object can be used to register event or hook handlers, raise new Zeek
events, invoking Zeek side functions, etc. This is similar to the global
``document`` object in a browser, but for Zeek functionality.

The API documentation for the global ``zeek`` object created is available
in the `ZeekJS documentation`_.

.. note: External due to requiring npm/jsdoc during building.

The following script calls the :zeek:see:`zeek_version` built-in
function and uses JavaScript's ``console.log()`` for printing a Hello message
within a ``zeek_init`` handler:

.. literalinclude:: js/hello.js
   :caption: hello.js
   :language: javascript

.. code-block:: console

   $ zeek js/hello.js
   Hello, Zeek 6.0.0!


Execution Model
===============

There are two ways in which Zeek executes JavaScript code.

First, JavaScript event or hook handlers are added as additional ``Func::Body``
instances to the respective ``Func`` objects. These extra bodies
point to instances of a custom ``Stmt`` subclass with tag ``STMT_EXTERN``.
The ``Stmt::Exec()`` implementation of this class calls the listener function,
a ``v8::Function``, registered through ``zeek.on()``.
When Zeek executes all bodies of an event or hook handler during ``Func::Invoke()``,
some bodies execute JavaScript functions instead of Zeek script statements.
This approach allows to register JavaScript listener functions using Zeek's priority
mechanism.  Further, changes done by JavaScript code to global Zeek variables or
record fields are visible to Zeek script and vice versa. In summary, execution
of Zeek and JavaScript code is interleaved when executing event or hook handlers.

Second, the Node.js IO loop (`libuv`_) is registered as an ``IOSource`` with
Zeek's main loop. When there's any IO activity in Node.js, libuv's backend
file descriptor becomes ready, waking up the Zeek main loop. Zeek then transfers
control through the registered ``IOsource`` to the JavaScript plugin which
runs the libuv IO loop until there's no more work to be done. At this point,
the plugin yields control back to Zeek's main loop, draining any queued events,
processing timers, or simply waiting for the next network packet to arrive.

From the above it follows that there is no parallel JavaScript code execution
happening in a separate thread. Zeek script and JavaScript execute interleaved
on Zeek's main thread, driven by the main loop's logic. This also implies that
long running JavaScript code will block Zeek's main loop and Zeek script
execution. This is no different than what would happen in a web browser or an
asynchronous Node.js network server, however, and the same applies to a long
running Zeek script event handler.


Types
=====

JavaScript doesn't support types as rich as Zeek and is further dynamically
typed. As of now, most atomic types like :zeek:see:`addr` or :zeek:see:`subnet` are created as JavaScript strings or another primitive type.
For example, values of type :zeek:see:`count` become JavaScript `BigInt`_ values.
:zeek:see:`time` and :zeek:see:`interval` are converted to numbers representing
seconds with :zeek:see:`time` representing the Unix timestamp.

A list of type conversions implemented is presented in the following table.

.. list-table:: Type Conversions

   * - Zeek
     - JavaScript

   * - bool
     - boolean (true, false)

   * - count
     - `BigInt`_

   * - int
     - `Number`_

   * - double
     - `Number`_

   * - interval
     - `Number`_ as seconds

   * - time
     - `Number`_ as unix timestamp in seconds

   * - string
     - string (latin1 encoding assumed)

   * - enum
     - string

   * - addr
     - string

   * - subnet
     - string

   * - port
     - `Object`_ with ``port`` an ``proto`` properties and a custom ``toJSON()`` method only returning the port

   * - vector
     - Copied as `Array`_, see :ref:`below <js-set-and-vector>`

   * - set
     - Copied as `Array`_, see :ref:`below <js-set-and-vector>`

   * - table
     - `Object`_ holding a reference to a Zeek table value

   * - record
     - `Object`_ holding a reference to a Zeek record value

Some type conversions are not implemented, they'll cause an error message
and have a ``null`` value in JavaScript. :zeek:see:`pattern` values is one
such example.

.. note::

   These type conversions may change in the future or become configurable via
   callbacks.

Record values
-------------

Record values are passed by reference from Zeek to JavaScript. That is,
JavaScript objects keep a pointer to the Zeek record they represent.
Holding a JavaScript object referencing a Zeek record value
will keep it alive within Zeek even if Zeek itself does not reference
it anymore. Updates to fields in Zeek become visible within JavaScript.
Updates to properties of such objects in JavaScript become visible in Zeek.

On the other hand, normal JavaScript objects (``{}`` or ``Object()``) are passed
from JavaScript to Zeek as new Zeek record values. Changes
to the original JavaScript object will not be reflected within Zeek.
In the example below, the ``intel_item`` JavaScript object will be converted to
a new :zeek:see:`Intel::Item` Zeek record which is then
passed to the :zeek:see:`Intel::insert` function. Modifying properties of
``intel_item`` after it has been inserted to the Intel data store has
no impact.

.. literalinclude:: js/intel-insert.js
   :caption: intel-insert.js
   :language: javascript

.. note::

   The background to this is that Zeek's base has no knowledge of anything
   JavaScript related, while the ZeekJS plugin does have intimate knowledge
   about Zeek values and internals.


Table values
------------

Table values are treated very similar to records. JavaScript objects representing
table values keep a reference to the Zeek value. Accessing multi-index Zeek tables
from JavaScript is not supported, however, as there's no easy way to translate
Zeek's multi-value keys to properties or map keys in JavaScript.

Global tables can be modified from JavaScript directly through the ``zeek.global_vars`` object.
The following script provides an example how to change the content
of :zeek:see:`Conn::analyzer_inactivity_timeouts` in JavaScript.
The update to the table becomes visible on the Zeek side and will be
in effect for future connections.

.. literalinclude:: js/global-vars.js
   :caption: global-vars.js
   :language: javascript

.. code-block:: console

   $ zeek global-vars.js -e 'event zeek_init() &priority=-5 { print "zeek", Conn::analyzer_inactivity_timeouts; }'
   js {
     [AllAnalyzers::ANALYZER_ANALYZER_SSH]: 42,
     [AllAnalyzers::ANALYZER_ANALYZER_FTP]: 3600
   }
   zeek, {
   [AllAnalyzers::ANALYZER_ANALYZER_SSH] = 42.0 secs,
   [AllAnalyzers::ANALYZER_ANALYZER_FTP] = 1.0 hr
   }

.. _js-set-and-vector:

Set and vector values
---------------------

The :zeek:see:`set` and :zeek:see:`vector` types are currently copied from
Zeek to JavaScript as `Array`_ objects. These objects don't reference the
original set or vector on the Zeek side. This means that mutation of the
JavaScript side objects via accessors on ``Array`` do not modify the
Zeek side value. However, objects referencing the Zeek record values within
these arrays are mutable.

This mainly becomes relevant if you wanted to modify state attached to
a connection within JavaScript. Re-assigning ``c.service`` below works
as expected, the ``c.service.push()`` approach on the other had would
not change the set on the Zeek-side.

.. literalinclude:: js/connection-service.js
   :caption: connection-service.js
   :language: javascript

.. code-block:: console

   $ zeek -r ../../traces/get.trace  ./connection-service.js
   service-from-js,http

.. note::

   The current approach was mostly chosen for implementation simplicity
   and the assumption that modifying Zeek side vectors or sets from JavaScript
   is an edge case. This may change in the future.

Any and zeek.as()
-----------------

Some of Zeek's function take a value of type :zeek:see:`any`. This makes it
impossible to implicitly convert from a JavaScript type to the appropriate
Zeek type.

The function ``zeek.as()`` can be leveraged within JavaScript to create an
object given a JavaScript value and a Zeek type name. That object is then
referencing a Zeek value and when used to call a function taking an any
parameter, the plugin directly threads through the referenced Zeek value
and the call succeeds.

.. literalinclude:: js/zeek-as.js
   :caption: zeek-as.js
   :language: javascript

The first call to ``zeek.invoke()`` throws an exception due to the failing
type conversion, the second one succeeds.

.. code-block:: console

   $ zeek -B plugin-Zeek-JavaScript zeek-as.js
   error: Unable to convert JS value '192.168.0.0/16' of type string to Zeek type any
   good: type_name is subnet


Debugging
---------

There might be limitations, surprises and bugs with the type conversions.
If Zeek was built with debugging enabled, the ``plugin-Zeek-JavaScript``
debug stream may provide some helpful clues.

.. code-block:: console

   $ ZEEK_DEBUG_LOG_STDERR=1 zeek -B plugin-Zeek-JavaScript hello.js
            0.000000/1685018723.447965 [plugin Zeek::JavaScript] Hooked .js file=hello.js (./hello.js)
            0.000000/1685018723.457376 [plugin Zeek::JavaScript] Hooked 1 .js files: Initializing!
            0.000000/1685018723.457639 [plugin Zeek::JavaScript] Init: Node initialized. Compiled with v19.8.1
            0.000000/1685018723.458774 [plugin Zeek::JavaScript] Init: V8 initialized. Version 10.8.168.25-node.12
            0.000000/1685018723.539618 [plugin Zeek::JavaScript] ExecuteAndWaitForInit: init() result=object 1
            0.000000/1685018723.539644 [plugin Zeek::JavaScript] ExecuteAndWaitForInit: zeek_javascript_init returned promise, state=0 - running JS loop
            0.000000/1685018723.551058 [plugin Zeek::JavaScript] Registering zeek_init priority=0, js_eh=0x603001cac710
            0.000000/1685018723.551120 [plugin Zeek::JavaScript] Registered zeek_init
   1685018723.601898/1685018723.621106 [plugin Zeek::JavaScript] ZeekInvoke: invoke for zeek_version
   1685018723.601898/1685018723.621177 [plugin Zeek::JavaScript] Invoke zeek_version with 0 args
   1685018723.601898/1685018723.621212 [plugin Zeek::JavaScript] ZeekInvoke: invoke for zeek_version returned: Hello, Zeek 6.0.0-dev.636-debug!
   1685018723.644485/1685018723.644726 [plugin Zeek::JavaScript] Done...
   1685018723.644485/1685018723.644754 [plugin Zeek::JavaScript] Done: uv_loop not alive anymore on iteration 0


Examples
========

HTTP API
--------

The following JavaScript file provides an HTTP API for generically invoking
Zeek functions and Zeek events using ``curl``. It's 60 lines of vanilla
Node.js JavaScript (with limited error handling), but allows for experiments
and runtime reconfiguration of a Zeek process that's hard to achieve with
Zeek provided functionality. Essentially, all that is used is ``zeek.event``
and ``zeek.invoke`` and relying on implicit type conversion to mostly do
the right thing.

The two supported endpoints are ``/events/<event_name>``
and ``/functions/<function_name>``. Arguments are passed in an ``args`` array
as JSON in the POST request's body.

.. literalinclude:: js/api.zeek
   :caption: api.zeek
   :language: zeek

.. literalinclude:: js/api.js
   :caption: api.js
   :language: javascript

.. code-block:: console

   $ zeek -C -i lo ./api.zeek
   Listening on 127.0.0.1:8080...
   listening on lo


As a first example, the :zeek:see:`get_net_stats` built-in function is
invoked and returns the current monitoring statistics in response.

.. code-block:: console

   $ curl -XPOST http://localhost:8080/functions/get_net_stats
   {
     "result": {
       "pkts_recvd": 3558,
       "pkts_dropped": 0,
       "pkts_link": 7126,
       "bytes_recvd": 27982155
     }
   }

Posting to ``/events/MyAPI::print_msg`` raises the ``MyAPI::print_msg`` event
implemented in the ``api.zeek`` file.

.. code-block:: console

   $ curl -4   --data-raw '{"args": ["Hello Zeek!"]}'  http://localhost:8080/events/MyAPI::print_msg
   {}

   # The Zeek process will output:
   ZEEK, print_msg, 1685121096.892404, Hello Zeek!

It is possible to runtime disable (and enable) analyzers as well by
leveraging :zeek:see:`Analyzer::disable_analyzer`. Here shown for the SSL analyzer.

.. code-block:: console

   $ curl -XPOST --data '{"args": ["AllAnalyzers::ANALYZER_ANALYZER_SSL"]}' localhost:8080/functions/Analyzer::disable_analyzer
   {
     "result": true
   }

.. todo::

   Using ``Analyzer::ANALYZER_SSL`` is currently not possible due to
   :zeek:see:`Analyzer::disable_analyzer` taking an :zeek:see:`AllAnalyzers::Tag`
   and the enum names are different.


As a fairly advanced example, creating a new :zeek:see:`Log::Filter` instance
for the :zeek:see:`Conn::LOG` stream at runtime using :zeek:see:`Log::add_filter`
is possible. Removal works, too.

.. code-block:: console

   $ curl -XPOST --data '{"args": ["Conn::LOG", {"name": "my-conn-rotate", "path": "my-conn-rotate", "include": ["ts", "id.orig_h", "id.res_h", "history"], "interv": 10}]}' \
       localhost:8080/functions/Log::add_filter
   {
     "result": true
   }

   $ curl -XPOST --data '{"args": ["Conn::LOG", "my-conn-rotate"]}' localhost:8080/functions/Log::remove_filter
   {
     "result": true
   }

This API can also be used to invoke :zeek:see:`terminate`, so you want to be
careful deploying this in an actual production environment:

.. code-block:: console

   $ curl -XPOST --data '{"args": []}' localhost:8080/functions/terminate
   {
     "result": true
   }

   # Zeek is now stopping with:
   1685121663.854714 <params>, line 1: received termination signal
   1685121663.854714 <params>, line 1: 53 packets received on interface lo, 0 (0.00%) dropped, 0 (0.00%) not processed

More
----
More examples can be found in the `ZeekJS documentation`_
and `repository <https://github.com/corelight/zeekjs/tree/main/examples>`_.


TypeScript
==========

`TypeScript`_ adds typing to JavaScript. While ZeekJS has no TypeScript awareness,
there's nothing preventing you from using it. Use ``tsc`` for type checking and
provide the produced ``.js`` files to Zeek.

You may need a ``zeek.d.ts`` file for the ``zeek`` object. A bare
`zeek.d.ts <https://github.com/corelight/zeekjs/pull/20/>`_ file has been
tested, but not integrated with ZeekJS at this point.


.. _ZeekJS documentation: https://zeekjs.readthedocs.io/en/latest/
.. _Node.js: https://nodejs.org/en
.. _ZeekJS: https://github.com/corelight/zeekjs
.. _BigInt: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt
.. _Number: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number
.. _Array: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array
.. _Object: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object
.. _HTTP server: https://nodejs.org/api/http.html#httpcreateserveroptions-requestlistener
.. _Redis: https://redis.io/
.. _TypeScript: https://www.typescriptlang.org/
.. _libuv: https://github.com/libuv/libuv
