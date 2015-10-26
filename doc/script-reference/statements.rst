Declarations and Statements
===========================

The Bro scripting language supports the following declarations and
statements.


Declarations
~~~~~~~~~~~~

+----------------------------+-----------------------------+
| Name                       | Description                 |
+============================+=============================+
| :bro:keyword:`module`      | Change the current module   |
+----------------------------+-----------------------------+
| :bro:keyword:`export`      | Export identifiers from the |
|                            | current module              |
+----------------------------+-----------------------------+
| :bro:keyword:`global`      | Declare a global variable   |
+----------------------------+-----------------------------+
| :bro:keyword:`const`       | Declare a constant          |
+----------------------------+-----------------------------+
| :bro:keyword:`type`        | Declare a user-defined type |
+----------------------------+-----------------------------+
| :bro:keyword:`redef`       | Redefine a global value or  |
|                            | extend a user-defined type  |
+----------------------------+-----------------------------+
| `function/event/hook`_     | Declare a function, event   |
|                            | handler, or hook            |
+----------------------------+-----------------------------+

Statements
~~~~~~~~~~

+----------------------------+------------------------+
| Name                       | Description            |
+============================+========================+
| :bro:keyword:`local`       | Declare a local        |
|                            | variable               |
+----------------------------+------------------------+
| :bro:keyword:`add`,        | Add or delete          |
| :bro:keyword:`delete`      | elements               |
+----------------------------+------------------------+
| :bro:keyword:`print`       | Print to stdout or a   |
|                            | file                   |
+----------------------------+------------------------+
| :bro:keyword:`for`,        | Loop over each         |
| :bro:keyword:`while`,      | element in a container |
| :bro:keyword:`next`,       | object (``for``), or   |
| :bro:keyword:`break`       | as long as a condition |
|                            | evaluates to true      |
|                            | (``while``).           |
+----------------------------+------------------------+
| :bro:keyword:`if`          | Evaluate boolean       |
|                            | expression and if true,|
|                            | execute a statement    |
+----------------------------+------------------------+
| :bro:keyword:`switch`,     | Evaluate expression    |
| :bro:keyword:`break`,      | and execute statement  |
| :bro:keyword:`fallthrough` | with a matching value  |
+----------------------------+------------------------+
| :bro:keyword:`when`        | Asynchronous execution |
+----------------------------+------------------------+
| :bro:keyword:`event`,      | Invoke or schedule     |
| :bro:keyword:`schedule`    | an event handler       |
+----------------------------+------------------------+
| :bro:keyword:`return`      | Return from function,  |
|                            | hook, or event handler |
+----------------------------+------------------------+

Declarations
------------

Declarations cannot occur within a function, hook, or event handler.

Declarations must appear before any statements (except those statements
that are in a function, hook, or event handler) in the concatenation of
all loaded Bro scripts.

.. bro:keyword:: module

    The "module" keyword is used to change the current module.  This
    affects the scope of any subsequently declared global identifiers.

    Example::

        module mymodule;

    If a global identifier is declared after a "module" declaration,
    then its scope ends at the end of the current Bro script or at the
    next "module" declaration, whichever comes first.  However, if a
    global identifier is declared after a "module" declaration, but inside
    an :bro:keyword:`export` block, then its scope ends at the end of the
    last loaded Bro script, but it must be referenced using the namespace
    operator (``::``) in other modules.

    There can be any number of "module" declarations in a Bro script.
    The same "module" declaration can appear in any number of different
    Bro scripts.


.. bro:keyword:: export

    An "export" block contains one or more declarations
    (no statements are allowed in an "export" block) that the current
    module is exporting.  This enables these global identifiers to be visible
    in other modules (but not prior to their declaration) via the namespace
    operator (``::``).  See the :bro:keyword:`module` keyword for a more
    detailed explanation.

    Example::

        export {
            redef enum Log::ID += { LOG };

            type Info: record {
                ts: time &log;
                uid: string &log;
            };

            const conntime = 30sec &redef;
        }

    Note that the braces in an "export" block are always required
    (they do not indicate a compound statement).  Also, no semicolon is
    needed to terminate an "export" block.

.. bro:keyword:: global

    Variables declared with the "global" keyword will be global.

    If a type is not specified, then an initializer is required so that
    the type can be inferred.  Likewise, if an initializer is not supplied,
    then the type must be specified.  In some cases, when the type cannot
    be correctly inferred, the type must be specified even when an
    initializer is present.  Example::

        global pi = 3.14;
        global hosts: set[addr];
        global ciphers: table[string] of string = table();

    Variable declarations outside of any function, hook, or event handler are
    required to use this keyword (unless they are declared with the
    :bro:keyword:`const` keyword instead).

    Definitions of functions, hooks, and event handlers are not allowed
    to use the "global" keyword.  However, function declarations (i.e., no
    function body is provided) can use the "global" keyword.

    The scope of a global variable begins where the declaration is located,
    and extends through all remaining Bro scripts that are loaded (however,
    see the :bro:keyword:`module` keyword for an explanation of how modules
    change the visibility of global identifiers).


.. bro:keyword:: const

    A variable declared with the "const" keyword will be constant.

    Variables declared as constant are required to be initialized at the
    time of declaration.  Normally, the type is inferred from the initializer,
    but the type can be explicitly specified.  Example::

        const pi = 3.14;
        const ssh_port: port = 22/tcp;

    The value of a constant cannot be changed.  The only exception is if the
    variable is a global constant and has the :bro:attr:`&redef`
    attribute, but even then its value can be changed only with a
    :bro:keyword:`redef`.

    The scope of a constant is local if the declaration is in a
    function, hook, or event handler, and global otherwise.

    Note that the "const" keyword cannot be used with either the "local"
    or "global" keywords (i.e., "const" replaces "local" and "global").


.. bro:keyword:: type

   The "type" keyword is used to declare a user-defined type.  The name
   of this new type has global scope and can be used anywhere a built-in
   type name can occur.

   The "type" keyword is most commonly used when defining a
   :bro:type:`record` or an :bro:type:`enum`, but is also useful when
   dealing with more complex types.

   Example::

       type mytype: table[count] of table[addr, port] of string;
       global myvar: mytype;

.. bro:keyword:: redef

    There are three ways that "redef" can be used:  to change the value of
    a global variable (but only if it has the :bro:attr:`&redef` attribute),
    to extend a record type or enum type, or to specify
    a new event handler body that replaces all those that were previously
    defined.

    If you're using "redef" to change a global variable (defined using either
    :bro:keyword:`const` or :bro:keyword:`global`), then the variable that you
    want to change must have the :bro:attr:`&redef` attribute.  If the variable
    you're changing is a table, set, or pattern, you can use ``+=`` to add
    new elements, or you can use ``=`` to specify a new value (all previous
    contents of the object are removed).  If the variable you're changing is a
    set or table, then you can use the ``-=`` operator to remove the
    specified elements (nothing happens for specified elements that don't
    exist).  If the variable you are changing is not a table, set, or pattern,
    then you must use the ``=`` operator.

    Examples::

        redef pi = 3.14;

    If you're using "redef" to extend a record or enum, then you must
    use the ``+=`` assignment operator.
    For an enum, you can add more enumeration constants, and for a record
    you can add more record fields (however, each record field in the "redef"
    must have either the :bro:attr:`&optional` or :bro:attr:`&default`
    attribute).

    Examples::

        redef enum color += { Blue, Red };
        redef record MyRecord += { n2:int &optional; s2:string &optional; };

    If you're using "redef" to specify a new event handler body that
    replaces all those that were previously defined (i.e., any subsequently
    defined event handler body will not be affected by this "redef"), then
    the syntax is the same as a regular event handler definition except for
    the presence of the "redef" keyword.

    Example::

        redef event myevent(s:string) { print "Redefined", s; }


.. _function/event/hook:

**function/event/hook**
    For details on how to declare a :bro:type:`function`,
    :bro:type:`event` handler, or :bro:type:`hook`,
    see the documentation for those types.


Statements
----------

Statements (except those contained within a function, hook, or event
handler) can appear only after all global declarations in the concatenation
of all loaded Bro scripts.

Each statement in a Bro script must be terminated with a semicolon (with a
few exceptions noted below).  An individual statement can span multiple
lines.

Here are the statements that the Bro scripting language supports.

.. bro:keyword:: add

    The "add" statement is used to add an element to a :bro:type:`set`.
    Nothing happens if the specified element already exists in the set.

    Example::

        local myset: set[string];
        add myset["test"];

.. bro:keyword:: break

    The "break" statement is used to break out of a :bro:keyword:`switch`,
    :bro:keyword:`for`, or :bro:keyword:`while` statement.


.. bro:keyword:: delete

    The "delete" statement is used to remove an element from a
    :bro:type:`set` or :bro:type:`table`.  Nothing happens if the
    specified element does not exist in the set or table.

    Example::

        local myset = set("this", "test");
        local mytable = table(["key1"] = 80/tcp, ["key2"] = 53/udp);
        delete myset["test"];
        delete mytable["key1"];

.. bro:keyword:: event

    The "event" statement immediately queues invocation of an event handler.

    Example::

        event myevent("test", 5);

.. bro:keyword:: fallthrough

    The "fallthrough" statement can be used as the last statement in a
    "case" block to indicate that execution should continue into the
    next "case" or "default" label.

    For an example, see the :bro:keyword:`switch` statement.

.. bro:keyword:: for

    A "for" loop iterates over each element in a string, set, vector, or
    table and executes a statement for each iteration.  Currently,
    modifying a container's membership while iterating over it may
    result in undefined behavior, so avoid adding or removing elements
    inside the loop.

    For each iteration of the loop, a loop variable will be assigned to an
    element if the expression evaluates to a string or set, or an index if
    the expression evaluates to a vector or table.  Then the statement
    is executed.  However, the statement will not be executed if the expression
    evaluates to an object with no elements.

    If the expression is a table or a set with more than one index, then the
    loop variable must be specified as a comma-separated list of different
    loop variables (one for each index), enclosed in brackets.

    A :bro:keyword:`break` statement can be used at any time to immediately
    terminate the "for" loop, and a :bro:keyword:`next` statement can be
    used to skip to the next loop iteration.

    Note that the loop variable in a "for" statement is not allowed to be
    a global variable, and it does not need to be declared prior to the "for"
    statement.  The type will be inferred from the elements of the
    expression.

    Example::

        local myset = set(80/tcp, 81/tcp);
        local mytable = table([10.0.0.1, 80/tcp]="s1", [10.0.0.2, 81/tcp]="s2");

        for (p in myset)
            print p;

        for ([i,j] in mytable) {
            if (mytable[i,j] == "done")
                break;
            if (mytable[i,j] == "skip")
                next;
            print i,j;
        }


.. bro:keyword:: if

    Evaluates a given expression, which must yield a :bro:type:`bool` value.
    If true, then a specified statement is executed.  If false, then
    the statement is not executed.  Example::

        if ( x == 2 ) print "x is 2";


    However, if the expression evaluates to false and if an "else" is
    provided, then the statement following the "else" is executed.  Example::

        if ( x == 2 )
            print "x is 2";
        else
            print "x is not 2";

.. bro:keyword:: local

    A variable declared with the "local" keyword will be local.  If a type
    is not specified, then an initializer is required so that the type can
    be inferred.  Likewise, if an initializer is not supplied, then the
    type must be specified.

    Examples::

        local x1 = 5.7;
        local x2: double;
        local x3: double = 5.7;

    Variable declarations inside a function, hook, or event handler are
    required to use this keyword (the only two exceptions are variables
    declared with :bro:keyword:`const`, and variables implicitly declared in a
    :bro:keyword:`for` statement).

    The scope of a local variable starts at the location where it is declared
    and persists to the end of the function, hook,
    or event handler in which it is declared (this is true even if the
    local variable was declared within a `compound statement`_ or is the loop
    variable in a "for" statement).


.. bro:keyword:: next

    The "next" statement can only appear within a :bro:keyword:`for` or
    :bro:keyword:`while` loop.  It causes execution to skip to the next
    iteration.


.. bro:keyword:: print

    The "print" statement takes a comma-separated list of one or more
    expressions.  Each expression in the list is evaluated and then converted
    to a string.  Then each string is printed, with each string separated by
    a comma in the output.

    Examples::

        print 3.14;
        print "Results", x, y;

    By default, the "print" statement writes to the standard
    output (stdout).  However, if the first expression is of type
    :bro:type:`file`, then "print" writes to that file.

    If a string contains non-printable characters (i.e., byte values that are
    not in the range 32 - 126), then the "print" statement converts each
    non-printable character to an escape sequence before it is printed.

    For more control over how the strings are formatted, see the :bro:id:`fmt`
    function.

.. bro:keyword:: return

    The "return" statement immediately exits the current function, hook, or
    event handler.  For a function, the specified expression (if any) is
    evaluated and returned.  A "return" statement in a hook or event handler
    cannot return a value because event handlers and hooks do not have
    return types.

    Examples::

        function my_func(): string
        {
            return "done";
        }

        event my_event(n: count)
        {
            if ( n == 0 ) return;

            print n;
        }

    There is a special form of the "return" statement that is only allowed
    in functions.  Syntactically, it looks like a :bro:keyword:`when` statement
    immediately preceded by the "return" keyword.  This form of the "return"
    statement is used to specify a function that delays its result (such a
    function can only be called in the expression of a :bro:keyword:`when`
    statement).  The function returns at the time the "when"
    statement's condition becomes true, and the function returns the value
    that the "when" statement's body returns (or if the condition does
    not become true within the specified timeout interval, then the function
    returns the value that the "timeout" block returns).

    Example::

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

      event bro_init()
            {
            # Installs a trigger which fires if a() returns 42.
            when ( a() == 42 )
                print "expected result";

            print "Waiting for a() to return...";
            X["a"] = 42;
            }


.. bro:keyword:: schedule

    The "schedule" statement is used to raise a specified event with
    specified parameters at a later time specified as an :bro:type:`interval`.

    Example::

        schedule 30sec { myevent(x, y, z) };

    Note that the braces are always required (they do not indicate a
    `compound statement`_).

    Note that "schedule" is actually an expression that returns a value
    of type "timer", but in practice the return value is not used.

.. bro:keyword:: switch

    A "switch" statement evaluates a given expression and jumps to
    the first "case" label which contains a matching value (the result of the
    expression must be type-compatible with all of the values in all of the
    "case" labels).  If there is no matching value, then execution jumps to
    the "default" label instead, and if there is no "default" label then
    execution jumps out of the "switch" block.

    Here is an example (assuming that "get_day_of_week" is a
    function that returns a string)::

        switch get_day_of_week()
            {
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

    A "switch" block can have any number of "case" labels, and one
    optional "default" label.

    A "case" label can have a comma-separated list of
    more than one value.  A value in a "case" label can be an expression,
    but it must be a constant expression (i.e., the expression can consist
    only of constants).

    Each "case" and the "default" block must
    end with either a :bro:keyword:`break`, :bro:keyword:`fallthrough`, or
    :bro:keyword:`return` statement (although "return" is allowed only
    if the "switch" statement is inside a function, hook, or event handler).
    If a "case" (or "default") block contain more than one statement, then
    there is no need to wrap them in braces.

    Note that the braces in a "switch" statement are always required (these
    do not indicate the presence of a `compound statement`_), and that no
    semicolon is needed at the end of a "switch" statement.


.. bro:keyword:: when

    Evaluates a given expression, which must result in a value of type
    :bro:type:`bool`.  When the value of the expression becomes available
    and if the result is true, then a specified statement is executed.

    In the following example, if the expression evaluates to true, then
    the "print" statement is executed::

        when ( (local x = foo()) && x == 42 )
            print x;

    However, if a timeout is specified, and if the expression does not
    evaluate to true within the specified timeout interval, then the
    statement following the "timeout" keyword is executed::

        when ( (local x = foo()) && x == 42 )
            print x;
        timeout 5sec {
            print "timeout";
        }

    Note that when a timeout is specified the braces are
    always required (these do not indicate a `compound statement`_).

    The expression in a "when" statement can contain a declaration of a local
    variable but only if the declaration is written in the form
    "local *var* = *init*" (example: "local x = myfunction()").  This form
    of a local declaration is actually an expression, the result of which
    is always a boolean true value.

    The expression in a "when" statement can contain an asynchronous function
    call such as :bro:id:`lookup_hostname` (in fact, this is the only place
    such a function can be called), but it can also contain an ordinary
    function call.  When an asynchronous function call is in the expression,
    then Bro will continue processing statements in the script following
    the "when" statement, and when the result of the function call is available
    Bro will finish evaluating the expression in the "when" statement.
    See the :bro:keyword:`return` statement for an explanation of how to
    create an asynchronous function in a Bro script.

.. bro:keyword:: while

    A "while" loop iterates over a body statement as long as a given
    condition remains true.

    A :bro:keyword:`break` statement can be used at any time to immediately
    terminate the "while" loop, and a :bro:keyword:`next` statement can be
    used to skip to the next loop iteration.

    Example::

        local i = 0;

        while ( i < 5 )
            print ++i;

        while ( some_cond() )
            {
            local finish_up = F;

            if ( skip_ahead() )
                next;

            [...]

            if ( finish_up )
                break;

            [...]
            }

.. _compound statement:

**compound statement**
    A compound statement is created by wrapping zero or more statements in
    braces ``{ }``.  Individual statements inside the braces need to be
    terminated by a semicolon, but a semicolon is not needed at the end
    (outside of the braces) of a compound statement.

    A compound statement is required in order to execute more than one
    statement in the body of a :bro:keyword:`for`, :bro:keyword:`while`,
    :bro:keyword:`if`, or :bro:keyword:`when` statement.

    Example::

        if ( x == 2 ) {
            print "x is 2";
            ++x;
        }

    Note that there are other places in the Bro scripting language that use
    braces, but that do not indicate the presence of a compound
    statement (these are noted in the documentation).

.. _null:

**null statement**
    The null statement (executing it has no effect) consists of just a
    semicolon.  This might be useful during testing or debugging a Bro script
    in places where a statement is required, but it is probably not useful
    otherwise.

    Example::

        if ( x == 2 )
            ;

