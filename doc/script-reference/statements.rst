Declarations and Statements
===========================

The Zeek scripting language supports the following declarations_ and
statements_.

Declarations
------------

Declarations cannot occur within a function, hook, or event handler.

Declarations must appear before any statements (except those statements
that are in a function, hook, or event handler) in the concatenation of
all loaded Zeek scripts.

.. list-table::
  :header-rows: 1

  * - Name
    - Description

  * - :zeek:keyword:`module`
    - Change the current module

  * - :zeek:keyword:`export`
    - Export identifiers from the current module

  * - :zeek:keyword:`global`
    - Declare a global variable

  * - :zeek:keyword:`const`
    - Declare a constant

  * - :zeek:keyword:`option`
    - Declare a configuration option

  * - :zeek:keyword:`type`
    - Declare a user-defined type

  * - :zeek:keyword:`redef`
    - Redefine a global value or extend a user-defined type

  * - `Callables`_: :zeek:type:`function`, :zeek:type:`event`, :zeek:type:`hook`
    - Declare a function, event handler, or hook


.. zeek:keyword:: module

module
~~~~~~

The ``module`` keyword is used to change the current module.  This
affects the scope of any subsequently declared global identifiers.

Example:

.. code-block:: zeek

    module mymodule;

If a global identifier is declared after a ``module`` declaration,
then its scope ends at the end of the current Zeek script or at the
next ``module`` declaration, whichever comes first.  However, if a
global identifier is declared after a ``module`` declaration, but inside
an :zeek:keyword:`export` block, then its scope ends at the end of the
last loaded Zeek script, but it must be referenced using the namespace
operator (``::``) in other modules.

There can be any number of ``module`` declarations in a Zeek script.
The same ``module`` declaration can appear in any number of different
Zeek scripts.

The reserved module name ``GLOBAL`` switches to the default global
namespace. This comes in handy if you're working in a module context but want to
define something globally, without the module's namespacing. For example, the
:ref:`Notice Framework <notice-framework>` uses this approach to define the
``NOTICE()`` function.

.. zeek:keyword:: export

export
~~~~~~

An ``export`` block contains one or more declarations
(no statements are allowed in an ``export`` block) that the current
module is exporting.  This enables these global identifiers to be visible
in other modules (but not prior to their declaration) via the namespace
operator (``::``).  See the :zeek:keyword:`module` keyword for a more
detailed explanation.

Example:

.. code-block:: zeek

    export {
        redef enum Log::ID += { LOG };

        type Info: record {
            ts: time &log;
            uid: string &log;
        };

        const conntime = 30sec &redef;
    }

Note that the braces in an ``export`` block are always required
(they do not indicate a compound statement).  Also, no semicolon is
needed to terminate an ``export`` block.


.. zeek:keyword:: global

global
~~~~~~

Variables declared with the ``global`` keyword will have global scope.

If a type is not specified, then an initializer is required so that
the type can be inferred.  Likewise, if an initializer is not supplied,
then the type must be specified.  In some cases, when the type cannot
be correctly inferred, the type must be specified even when an
initializer is present.  Example:

.. code-block:: zeek

    global pi = 3.14;
    global hosts: set[addr];
    global ciphers: table[string] of string = table();

Variable declarations outside of any function, hook, or event handler are
required to use this keyword (unless they are declared with the
:zeek:keyword:`const` keyword instead).

Definitions of functions, hooks, and event handlers are not allowed
to use the ``global`` keyword.  However, function declarations (i.e., no
function body is provided) can use the ``global`` keyword.

The scope of a global variable begins where the declaration is located,
and extends through all remaining Zeek scripts that are loaded (however,
see the :zeek:keyword:`module` keyword for an explanation of how modules
change the visibility of global identifiers).


.. zeek:keyword:: const

const
~~~~~

A variable declared with the ``const`` keyword cannot be changed by
reassignment.  Variables declared as constant are required to be initialized at
the time of declaration.  Normally, the type is inferred from the initializer,
but the type can be explicitly specified.  Example:

.. code-block:: zeek

    const pi = 3.14;
    const ssh_port: port = 22/tcp;

The value of a constant cannot be changed:

.. code-block:: zeek

    ssh_port = 80/tcp; # "error [...]: const is not a modifiable lvalue (ssh_port)"

The only exception is if the variable is a global constant and has the
:zeek:attr:`&redef` attribute, but even then its value can be changed only with
a :zeek:keyword:`redef` declaration:

.. code-block:: zeek

    const ssh_port: port = 22/tcp &redef;
    # ...
    redef ssh_port = 2222/tcp; # ok

Const-ness does not apply to members of existing container type instances, which
can still be modified, added, or removed:

.. code-block:: zeek

    const ssh_ports = vector(22/tcp, 2222/tcp);
    # ...
    ssh_ports += 222/tcp; # ok
    ssh_ports = vector(222/tcp); # error [...]: const is not a modifiable lvalue (ssh_ports)

The scope of a constant is local if the declaration is in a
function, hook, or event handler, and global otherwise.

Note that the ``const`` keyword cannot be used with either the ``local``
or ``global`` keywords (i.e., ``const`` is an alternative to either
``local`` or ``global``).


.. zeek:keyword:: option

option
~~~~~~

A variable declared with the ``option`` keyword is a configuration option.

Options are required to be initialized at the
time of declaration.  Normally, the type is inferred from the initializer,
but the type can be explicitly specified.  Example:

.. code-block:: zeek

    option hostname = "host-1";
    option peers: set[addr] = {};

The initial value can be redefined with a :zeek:keyword:`redef`.

The value of an option cannot be changed by an assignment statement, but
it can be changed by either the :zeek:id:`Config::set_value` function or
by changing a config file specified in :zeek:id:`Config::config_files`.

The scope of an option is global.

Note that an ``option`` declaration cannot also use the ``local``,
``global``, or ``const`` keywords.


.. zeek:keyword:: type

type
~~~~

The ``type`` keyword is used to declare a user-defined type.  The name
of this new type has global scope and can be used anywhere a built-in
type name can occur.

The ``type`` keyword is most commonly used when defining a
:zeek:type:`record` or an :zeek:type:`enum`, but is also useful when
dealing with more complex types.

Example:

.. code-block:: zeek

   type mytype: table[count] of table[addr, port] of string;
   global myvar: mytype;


.. zeek:keyword:: redef

redef
~~~~~

There are several ways that ``redef`` can be used:  to redefine the initial
value of a global variable or runtime option, to extend a record type or
enum type, to add or remove attributes of record fields, or to specify a
new event handler body that replaces all those that were previously defined.

Redefining Initial Values
^^^^^^^^^^^^^^^^^^^^^^^^^

If you're using ``redef`` to redefine the initial value of a global variable
(defined using either :zeek:keyword:`const` or :zeek:keyword:`global`), then
the variable that you want to change must have the :zeek:attr:`&redef`
attribute.  You can use ``redef`` to redefine the initial value of a
runtime option (defined using :zeek:keyword:`option`) even if it doesn't
have the :zeek:attr:`&redef` attribute.

If the variable you're changing is a table, set, vector, or pattern, you can
use ``+=`` to add new elements, or you can use ``=`` to specify a new value
(all previous contents of the object are removed).  If the variable you're
changing is a set or table, then you can use the ``-=`` operator to remove
the specified elements (nothing happens for specified elements that don't
exist).  If the variable you are changing is not a table, set, or pattern,
then you must use the ``=`` operator.

Examples:

.. code-block:: zeek

    redef pi = 3.14;
    redef set_of_ports += { 22/tcp, 53/udp };

Extending Records Types or Enums
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you're using ``redef`` to extend a record or enum, then you must
use the ``+=`` assignment operator.
For an enum, you can add more enumeration constants, and for a record
you can add more record fields (however, each record field in the ``redef``
must have either the :zeek:attr:`&optional` or :zeek:attr:`&default`
attribute).

Examples:

.. code-block:: zeek

    redef enum color += { Blue, Red };
    redef record MyRecord += { n2:int &optional; s2:string &optional; };

Changing Attributes of Record Fields
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. versionadded:: 5.1

If you're using ``redef`` to change the attributes of a record field, you must
use either the ``+=`` or ``-=`` assignment operator and specify the record field
by means of the field access operator ``$`` using the record type's name.

Only the ``&log`` attribute can currently be removed from or added to an
existing record field. This enables removal of columns from logs that are
uninteresting for a given deployment or include columns that do not yet have
the ``&log`` attribute.

.. note::

   The :ref:`logging framework <framework-logging>` provides a separate
   mechanism to exlude columns from logs by means of the ``exclude`` field
   on :zeek:see:`Log::Filter` instances.

Examples:

.. code-block:: zeek

    redef record Notice::Info$email_dest -= { &log }

    redef record X509::Certificate$tbs_sig_alg += { &log };

Replacing Event Handlers
^^^^^^^^^^^^^^^^^^^^^^^^

If you're using ``redef`` to specify a new event handler body that
replaces all those that were previously defined (i.e., any subsequently
defined event handler body will not be affected by this ``redef``), then
the syntax is the same as a regular event handler definition except for
the presence of the ``redef`` keyword.

Example:

.. code-block:: zeek

    redef event myevent(s:string) { print "Redefined", s; }


.. _function/event/hook:

Callables
~~~~~~~~~

Callable types come in three flavors: :zeek:type:`function`, :zeek:type:`event`
handler, and :zeek:type:`hook`. All come with associated arguments and
bodies of statements. The following table compares and contrasts:

.. list-table::
  :header-rows: 1

  * - **Features**
    - :zeek:type:`function`
    - :zeek:type:`hook`
    - :zeek:type:`event`

  * - **Anonymity**
    - Yes
    - No
    - No

  * - **Multiple bodies and priorities**
    - No
    - Yes
    - Yes

  * - **Immediate invocation**
    - Yes
    - Yes
    - No

  * - **Scheduling**
    - No
    - No
    - Yes

  * - **Default arguments**
    - Yes
    - Yes
    - Yes

  * - **Container argument mutability**
    - Yes if synchronous, no if :ref:`asynchronous <asynchronous-return>`
    - Yes
    - Yes

  * - **Alternate declarations**
    - No
    - Yes
    - Yes

  * - **Return value**
    - Yes
    - Yes
    - No

Anonymity
^^^^^^^^^

While Zeek does support the concept of :ref:`anonymous functions
<anonymous-function>` (i.e., lambdas), hooks and events cannot be
anonymous. They are referenced by their names. As an example, reducer functions
in the :ref:`SumStats framework <sumstats-framework>` are often implemented as
lambda functions.

Multiple bodies and priorities
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Functions cannot have multiple bodies, however, hooks and events can. This means
that different scripts can add additional bodies to a hook or event associated
with a unique name. When an event or hook is executed, Zeek needs a way to order
the execution. This is accomplished with the numerical  :zeek:attr:`&priority`
attribute: by default, a hook’s or event’s body has a priority of zero, but any
integer-range value is valid.

Immediate invocation
^^^^^^^^^^^^^^^^^^^^

Functions and hook bodies are executed immediately. That means if a script is
being interpreted and a line contains a function call, execution flow is
immediately passed to that function (or hook). This does not happen for
events. Events are pushed onto an event queue within Zeek and are handled as
time passes.

Scheduling
^^^^^^^^^^

Functions and hooks cannot be scheduled like events can. Scheduling places an
event onto the event queue and is the equivalent to immediately invoking a
function or hook. Attempting to schedule a function or a hook results in the
same syntax error: "function invoked as an event".

Default arguments
^^^^^^^^^^^^^^^^^

Functions, hooks, and events all support :ref:`default values <default-values>`
for their arguments.

Container argument mutability
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When argument types are container types (such as records or tables), mutating the
arguments within the body of a function, hook, or event causes the argument to
retain that mutation: container types are passed by reference while atomic types
are passed by value.

Asynchronous functions are an exception: the evaluation of :zeek:keyword:`when`
statements invokes such functions with copies of their arguments, causing
modifications made inside the asynchronous function to be lost. Please refer to
:ref:`asynchronous return <asynchronous-return>` for possible workarounds.

Alternate declarations
^^^^^^^^^^^^^^^^^^^^^^

Hooks and events do support alternate prototype declarations. This means that a
set or scripts may define a single event (or hook) name multiple times with
different argument sets. This is often referred to as overloading in other
languages. Functions do not support alternate prototype declarations.

Return value
^^^^^^^^^^^^

All functions must return a value. However, functions with no explicit return
type implicitly return void. This can seem a bit odd as void isn’t a valid Zeek
type.  A hook body is allowed to return before it breaks. Hooks may return
either a boolean type or void, but aren’t required to return any value.  Events
cannot return a value because they are scheduled through the event loop and
don’t have a caller to return to.

For further details on how to declare callables, see the  :zeek:type:`function`,
:zeek:type:`event` handler, and :zeek:type:`hook` documentation.

Statements
----------

Statements (except those contained within a function, hook, or event
handler) can appear only after all global declarations in the concatenation
of all loaded Zeek scripts.

Each statement in a Zeek script must be terminated with a semicolon (with a
few exceptions noted below).  An individual statement can span multiple
lines.

Here are the statements that the Zeek scripting language supports.

.. list-table::
  :header-rows: 1

  * - Name
    - Description

  * - :zeek:keyword:`local`
    - Declare a local variable

  * - :zeek:keyword:`add`, :zeek:keyword:`delete`
    - Add or delete elements

  * - :zeek:keyword:`assert`
    - Runtime assertion

  * - :zeek:keyword:`print`
    - Print to stdout or a file

  * - :zeek:keyword:`for`, :zeek:keyword:`while`,
      :zeek:keyword:`next`, :zeek:keyword:`break`
    - Loop over each element in a container object (``for``), or as long as a
      condition evaluates to true (``while``).

  * - :zeek:keyword:`if`
    - Evaluate boolean and if true, execute a statement

  * - :zeek:keyword:`switch`, :zeek:keyword:`break`, :zeek:keyword:`fallthrough`
    - Evaluate expression and execute statement with a matching value

  * - :zeek:keyword:`when`
    - Asynchronous execution

  * - :zeek:keyword:`event`, :zeek:keyword:`schedule`
    - Invoke or schedule an event handler

  * - :zeek:keyword:`return`
    - Return from function, hook, or event handler


.. zeek:keyword:: add

add
~~~

The ``add`` statement is used to add an element to a :zeek:type:`set`.
Nothing happens if the specified element already exists in the set.

Example:

.. code-block:: zeek

    local myset: set[string];
    add myset["test"];


.. zeek:keyword:: assert

assert
~~~~~~

.. versionadded:: 6.1

The ``assert`` statement can be used for runtime assertion checks or as a building
block for a testing framework. It takes an expression ``expr`` of type
:zeek:see:`bool` and an optional message of type :zeek:see:`string`.
If ``expr`` at runtime evaluates to ``F``, the string representation
of the expression and the given message, if any, are logged
via :zeek:see:`Reporter::error` by default.

Script execution for a given event handler stops with a failing ``assert`` statement
comparable to a scripting runtime error after generating the log.

Example:

.. literalinclude:: assert_1.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

This script prints the following messages to stderr, as well as logging them to
``reporter.log``.

.. code-block:: console

   $ zeek assert_1.zeek
   error in ./assert_1.zeek, line 6: assertion failure: 40 < x
   error in ./assert_1.zeek, line 12: assertion failure: 40 < x (37 is not greater than 40)

.. note::

   Zeek's exit code in this example will be ``0``, indicating success.
   Script errors other than those in a ``zeek_init()`` handler are not
   reflected in Zeek's exit code.


The logging behavior of failing assert statements can be customized using the
:zeek:see:`assertion_failure` or zeek:see:`assertion_result` hook.
Using the :zeek:see:`break` statement in either hook allows for suppression
of the the default log generation.
The :zeek:see:`assertion_result` hook is targeted for testing frameworks as it
is likely prohibitively expensive for use in a live production environment due
to being invoked for every ``assert`` statement execution.


.. zeek:keyword:: break

break
~~~~~

The ``break`` statement is used to break out of a :zeek:keyword:`switch`,
:zeek:keyword:`for`, or :zeek:keyword:`while` statement.


.. zeek:keyword:: delete

delete
~~~~~~

The ``delete`` statement is used to remove an element from a
:zeek:type:`set` or :zeek:type:`table`, or to remove a value from
a :zeek:type:`record` field that has the :zeek:attr:`&optional` attribute.
When attempting to remove an element from a set or table,
nothing happens if the specified index does not exist.
When attempting to remove a value from an ``&optional`` record field,
nothing happens if that field doesn't have a value.

Example:

.. code-block:: zeek

    local myset = set("this", "test");
    local mytable = table(["key1"] = 80/tcp, ["key2"] = 53/udp);
    local myrec = MyRecordType($a = 1, $b = 2);

    delete myset["test"];
    delete mytable["key1"];

    # In this example, "b" must have the "&optional" attribute
    delete myrec$b;

.. versionadded:: 7.0

The ``delete`` statement can also be used to remove all elements from
a :zeek:type:`set`, :zeek:type:`table` or :zeek:type:`vector`.

Example:

.. code-block:: zeek

    local myset = set("this", "test");
    delete myset;


.. zeek:keyword:: event

event
~~~~~

The ``event`` statement immediately queues invocation of an event handler.

Example:

.. code-block:: zeek

    event myevent("test", 5);


.. zeek:keyword:: fallthrough

fallthrough
~~~~~~~~~~~

The ``fallthrough`` statement can be used within a ``case`` block to
indicate that execution should continue at the next ``case`` or ``default``
label.

For an example, see the :zeek:keyword:`switch` statement.

.. zeek:keyword:: for

for
~~~

A ``for`` loop iterates over each element in a string, set, vector, or
table and executes a statement for each iteration (note that the order
in which the loop iterates over the elements in a set or a table is
nondeterministic).  However, no loop iterations occur if the string,
set, vector, or table is empty.

For each iteration of the loop, a loop variable will be assigned to an
element if the expression evaluates to a string or set, or an index if
the expression evaluates to a vector or table.  Then the statement
is executed.

If the expression is a table or a set with more than one index, then the
loop variable must be specified as a comma-separated list of different
loop variables (one for each index), enclosed in brackets.

If the expression is a table, keys and values can be iterated over at the
same time by specifying a key and value variable. Similarly, if the expression
is a vector, indices and values can be iterated over at the same time by
specifying an index and value variable.
The core exposes value variables for free, so this should be preferred to
accessing the values in a separate lookup inside the loop.

Note that the loop variable in a ``for`` statement is not allowed to be
a global variable, and it does not need to be declared prior to the ``for``
statement.  The type will be inferred from the elements of the
expression.

In some scenarios, the loop variable or parts of the table index may be
unused in the ``for`` loop's body. Zeek reserves ``_``, the blank identifier, as
an explicitly way to support capturing unused variables.

The blank identifier can be assigned expressions of any type, but it can
never be referenced.
For the ``for`` loop, this allows to use the blank identifier to capture
unused loop variables of differing types---something that isn't possible
with normal variables.
As a special case, all index variables of a table or set can be ignored with
a single blank identifier.
In fact, in current versions of Zeek, ignoring all index variables allows
for faster iteration and is therefore recommended to be used when possible.

Currently, modifying a container's membership while iterating over it may
result in undefined behavior, so do not add or remove elements
inside the loop.

A :zeek:keyword:`break` statement will immediately terminate the ``for``
loop, and a :zeek:keyword:`next` statement will skip to the next loop
iteration.

Example:

.. code-block:: zeek

    local myset = set(80/tcp, 81/tcp);
    local mytable = table([10.0.0.1, 80/tcp]="s1", [10.0.0.2, 81/tcp]="s2");
    local myvector = vector("zero", "one, "two");

    for ( p in myset )
        print p;

    for ( [i,j], val in mytable )
        {
        if (val == "done")
            break;
        if (val == "skip")
            next;
        print i,j;
        }

    for ( _, val in mytable )
        print val;

    for ( [i,_], _ in mytable )
        print i;

    for ( i, val in myvector )
        print i,val;

    for ( _, val in myvector )
        print val;


.. zeek:keyword:: if

if
~~

Evaluates a given expression, which must yield a :zeek:type:`bool` value.
If true, then a specified statement is executed.  If false, then
the statement is not executed.  Example:

.. code-block:: zeek

    if ( x == 2 ) print "x is 2";

However, if the expression evaluates to false and if an ``else`` is
provided, then the statement following the ``else`` is executed.  Example:

.. code-block:: zeek

    if ( x == 2 )
        print "x is 2";
    else
        print "x is not 2";


.. zeek:keyword:: local

local
~~~~~

A variable declared with the ``local`` keyword will be local.  If a type
is not specified, then an initializer is required so that the type can
be inferred.  Likewise, if an initializer is not supplied, then the
type must be specified.

Examples:

.. code-block:: zeek

    local x1 = 5.7;
    local x2: double;
    local x3: double = 5.7;

Variable declarations inside a function, hook, or event handler are
required to use this keyword (the only two exceptions are variables
declared with :zeek:keyword:`const`, and variables implicitly declared in a
:zeek:keyword:`for` statement).

The scope of a local variable starts at the location where it is declared
and persists to the end of the function, hook,
or event handler in which it is declared (this is true even if the
local variable was declared within a `compound statement`_ or is the loop
variable in a ``for`` statement).


.. zeek:keyword:: next

next
~~~~

The ``next`` statement can only appear within a :zeek:keyword:`for` or
:zeek:keyword:`while` loop.  It causes execution to skip to the next
iteration.


.. zeek:keyword:: print

print
~~~~~

The ``print`` statement takes a comma-separated list of one or more
expressions.  Each expression in the list is evaluated and then converted
to a string.  Then each string is printed, with each string separated by
a comma in the output.

Examples:

.. code-block:: zeek

    print 3.14;
    print "Results", x, y;

By default, the ``print`` statement writes to the standard
output (stdout).  However, if the first expression is of type
:zeek:type:`file`, then ``print`` writes to that file.

If a string contains non-printable characters (i.e., byte values that are
not in the range 32 - 126), then the ``print`` statement converts each
non-printable character to an escape sequence before it is printed.

For more control over how the strings are formatted, see the :zeek:id:`fmt`
function.


.. zeek:keyword:: return

return
~~~~~~

The ``return`` statement immediately exits the current function, hook, or
event handler.  For a function, the specified expression (if any) is
evaluated and returned.  A ``return`` statement in a hook or event handler
cannot return a value because event handlers and hooks do not have
return types.

Examples:

.. code-block:: zeek

    function my_func(): string
        {
        return "done";
        }

    event my_event(n: count)
        {
        if ( n == 0 ) return;

        print n;
        }

.. _asynchronous-return:

Asynchronous return
^^^^^^^^^^^^^^^^^^^

There is a special form of the ``return`` statement that is only allowed
in functions.  Syntactically, it looks like a :zeek:keyword:`when` statement
immediately preceded by the ``return`` keyword.  This form of the ``return``
statement is used to specify a function that delays its result: an
*asynchronous function*.
Such functions can only be called in the expression of a :zeek:keyword:`when`
statement).  The function returns at the time the ``when``
statement's condition becomes true, and the function returns the value
that the ``when`` statement's body returns (or if the condition does
not become true within the specified timeout interval, then the function
returns the value that the ``timeout`` block returns).

(Note that if you use the deprecated feature of not listing the *captures*
in your ``return when`` statement, then, in contrast to regular functions, your
asynchronous functions cannot make lasting modifications to
arguments that have aggregate types, because those values will be
deep-copied upon execution of the ``return when``.)

Example:

.. code-block:: zeek

  global X: table[string] of count;

  function a() : count
        {
        # This delays until condition becomes true.
        return when ( "a" in X )
              {
              return X["a"];
              }
        timeout 30 sec
              {
              return 0;
              }
        }

  event zeek_init()
        {
        # Installs a trigger which fires if a() returns 42.
        when ( a() == 42 )
            print "expected result";

        print "Waiting for a() to return...";
        X["a"] = 42;
        }


.. zeek:keyword:: schedule

schedule
~~~~~~~~

The ``schedule`` statement is used to raise a specified event with
specified parameters at a later time specified as an :zeek:type:`interval`.

Example:

.. code-block:: zeek

    schedule 30sec { myevent(x, y, z) };

.. note::

   The braces are always required here (that is, they do not indicate a
   `compound statement`_). Also, ``schedule`` is actually an expression that
   returns a value of type ``timer``, but in practice the return value is not
   used.

.. note::

  Always specify event names with their full module namespace. For example,
  if the above ``myevent`` lives in the ``MyModule`` module, then say the
  following even when working inside the module:

  .. code-block:: zeek

     schedule 30sec { MyModule::myevent(x, y, z) };

  See :ref:`event-namespacing-pitfall` for details.

.. note::

  Using ``schedule`` within :zeek:see:`zeek_init` does not usually have the
  desired behavior -- since :zeek:see:`network_time` is not yet initialized,
  the scheduled event may be dispatched upon processing the first network
  packet since that will update network-time from zero to the time associated
  with capturing that packet.  A typical workaround is to ignore the first
  time such an event is dispatched and simply re-schedule it or to instead
  schedule the first event from within the :zeek:see:`network_time_init` event.

.. zeek:keyword:: switch

switch
~~~~~~

A ``switch`` statement evaluates a given expression and jumps to
the first ``case`` label which contains a matching value (the result of the
expression must be type-compatible with all of the values in all of the
``case`` labels).  If there is no matching value, then execution jumps to
the ``default`` label instead, and if there is no ``default`` label then
execution jumps out of the ``switch`` block.

Here is an example (assuming that ``get_day_of_week`` is a
function that returns a string):

.. code-block:: zeek

    switch get_day_of_week() {
        case "Sa", "Su":
            print "weekend";
            fallthrough;
        case "Mo", "Tu", "We", "Th", "Fr":
            print "valid result";
            break;
        default:
            print "invalid result";
            break;
    }

A ``switch`` block can have any number of ``case`` labels, and one
optional ``default`` label.

A ``case`` label can have a comma-separated list of
more than one value.  A value in a ``case`` label can be an expression,
but it must be a constant expression (i.e., the expression can consist
only of constants).

Each ``case`` and the ``default`` block must
end with either a :zeek:keyword:`break`, :zeek:keyword:`fallthrough`, or
:zeek:keyword:`return` statement (although ``return`` is allowed only
if the ``switch`` statement is inside a function, hook, or event handler).

Note that the braces in a ``switch`` statement are always required (these
do not indicate the presence of a `compound statement`_), and that no
semicolon is needed at the end of a ``switch`` statement.

There is an alternative form of the switch statement that supports
switching by type rather than value.  This form of the switch statement
uses type-based versions of ``case``:

- ``case type t: ...``: Take branch if the value of the switch expression
  could be casted to type ``t`` (where ``t`` is the name of a Zeek script
  type, either built-in or user-defined).

- ``case type t as x: ...``: Same as above, but the casted value is
  available through ID ``x``.

Multiple types can be listed per branch, separated by commas (the ``type``
keyword must be repeated for each type in the list).

Example:

.. code-block:: zeek

    function example(v: any)
        {
        switch (v) {
        case type count as c:
                print "It's a count", c;
                break;

        case type bool, type addr:
                print "It's a bool or address";
                break;
        }
        }

Note that a single switch statement switches either by type or by value,
but not both.

Also note that the type-based switch statement will trigger a runtime
error if any cast in any ``case`` is an unsupported cast (see the
documentation of the type casting operator ``as``).

A type-casting ``case`` block is also not allowed to use a
:zeek:keyword:`fallthrough` statement since that could generally mean
entering another type-casting block. That is, the switched-upon value could
get cast to at least two different types, which is not a valid possibility.


.. _when-statement:
.. zeek:keyword:: when

when
~~~~

Evaluates a given expression, which must result in a value of type
:zeek:type:`bool`.  When the value of the expression becomes available
and if the result is true, then a specified statement is executed.

In the following example, if the expression evaluates to true, then
the ``print`` statement is executed:

.. code-block:: zeek

    when ( (local x = foo()) && x == 42 )
        {
        print x;
        }

However, if a timeout is specified, and if the expression does not
evaluate to true within the specified timeout interval, then the
statement following the ``timeout`` keyword is executed:

.. code-block:: zeek

    when ( (local x = foo()) && x == 42 )
        {
        print x;
        }
    timeout 5sec
        {
        print "timeout";
        }

Note that when a timeout is specified the braces are
always required (these do not indicate a `compound statement`_).

The expression in a ``when`` statement can contain a declaration of a local
variable but only if the declaration is written in the form
``local *var* = *init*`` (example: ``local x = myfunction()``).  This form
of a local declaration is actually an expression, the result of which
is always a boolean true value.

The expression in a ``when`` statement can contain an asynchronous function
call such as :zeek:id:`lookup_hostname` (in fact, this is the only place
such a function can be called), but it can also contain an ordinary
function call.  When an asynchronous function call is in the expression,
then Zeek will continue processing statements in the script following
the ``when`` statement, and when the result of the function call is available
Zeek will finish evaluating the expression in the ``when`` statement.
See the :zeek:keyword:`return` statement for an explanation of how to
create an asynchronous function in a Zeek script.

The elements of a ``when`` statement can include references to the local
variables of the function/event/hook body in which they appear (as well
as to global variables).  If they do, then you need to specify the locals
variables as *captures*, using ``[...]`` in the same manner as done for
:ref:`anonymous functions <anonymous-function>`.  By default captures are
done using *shallow-copying*, behaving like an assignment; you can add the
keyword
``copy`` to instead make a *deep* copy.

For example:

.. code-block:: zeek

    type r: record { x: int; y: int; };
    global g = r($x=100, $y=100);

    event zeek_init()
        {
        local l = r($x=1, $y=2);
        local l2 = r($x=3, $y=4);

        when [l, copy l2] ( g$x < 0 )
            {
            print l, l2;
            }

        l$x = 10;
        l2$x = 20;
        }

    event zeek_init() &priority=-10
        {
        g$x = -999;
        }

will print ``[x=10, y=2], [x=3, y=4]``, because, as a shallow copy, the
version of ``l`` inside the ``when`` statement will reflect the changes
made to its record after execution of the ``when`` statement; while the
version of ``l2`` will not, since it holds a deep copy of the record
made upon executing the ``when`` statement.

For the captures you need to list all of local variables used in the
statement: those in the initial condition, as well as those appearing in
the body or the ``timeout`` statement.  You do not need to list new
``local``'s introduce in the expression (such as ``local x = foo()`` in
the example given earlier above).

It also works, for now, to leave off the captures entirely, but this
form is deprecated.  It provides old-style semantics, in which every
local is automatically captured via deep-copy.

.. zeek:keyword:: while

while
~~~~~

A ``while`` loop iterates over a body statement as long as a given
condition remains true.

A :zeek:keyword:`break` statement can be used at any time to immediately
terminate the ``while`` loop, and a :zeek:keyword:`next` statement can be
used to skip to the next loop iteration.

Example:

.. code-block:: zeek

    local i = 0;

    while ( i < 5 )
        print ++i;

    while ( some_cond() )
        {
        local finish_up = F;

        if ( skip_ahead() )
            next;

        if ( finish_up )
            break;
        }


.. _compound statement:

Compound Statement
~~~~~~~~~~~~~~~~~~

A compound statement is created by wrapping zero or more statements in
braces ``{ }``.  Individual statements inside the braces need to be
terminated by a semicolon, but a semicolon is not needed at the end
(outside of the braces) of a compound statement.

A compound statement is required in order to execute more than one
statement in the body of a :zeek:keyword:`for`, :zeek:keyword:`while`,
:zeek:keyword:`if`, or :zeek:keyword:`when` statement.

Example:

.. code-block:: zeek

    if ( x == 2 )
        {
        print "x is 2";
        ++x;
        }

Note that there are other places in the Zeek scripting language that use
braces, but that do not indicate the presence of a compound
statement (these are noted in the documentation).


.. _null statement:

Null Statement
~~~~~~~~~~~~~~

The null statement (executing it has no effect) consists of just a
semicolon.  This might be useful during testing or debugging a Zeek script
in places where a statement is required, but it is probably not useful
otherwise.

Example:

.. code-block:: zeek

    if ( x == 2 )
        ;
