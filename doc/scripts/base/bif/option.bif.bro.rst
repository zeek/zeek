:tocdepth: 3

base/bif/option.bif.bro
=======================
.. bro:namespace:: GLOBAL
.. bro:namespace:: Option

Definitions of built-in functions that allow the scripting layer to
change the value of options and to be notified when option values change.

:Namespaces: GLOBAL, Option

Summary
~~~~~~~
Functions
#########
========================================================== ===================================
:bro:id:`Option::set`: :bro:type:`function`                Set an option to a new value.
:bro:id:`Option::set_change_handler`: :bro:type:`function` Set a change handler for an option.
========================================================== ===================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: Option::set

   :Type: :bro:type:`function` (ID: :bro:type:`string`, val: :bro:type:`any`, location: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`bool`

   Set an option to a new value. This change will also cause the option change
   handlers to be called.
   

   :ID: The ID of the option to update.
   

   :val: The new value of the option.
   

   :location: Optional parameter detailing where this change originated from.
   

   :returns: true on success, false when an error occurred.
   
   .. bro:see:: Option::set_change_handler Config::set_value
   
   .. note:: :bro:id:`Option::set` only works on one node and does not distribute
             new values across a cluster. The higher-level :bro:id:`Config::set_value`
             supports clusterization and should typically be used instead of this
             lower-level function.

.. bro:id:: Option::set_change_handler

   :Type: :bro:type:`function` (ID: :bro:type:`string`, on_change: :bro:type:`any`, priority: :bro:type:`int` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`) : :bro:type:`bool`

   Set a change handler for an option. The change handler will be
   called anytime :bro:id:`Option::set` is called for the option.
   

   :ID: The ID of the option for which change notifications are desired.
   

   :on_change: The function that will be called when a change occurs. The
              function can choose to receive two or three parameters: the first
              parameter is a string containing *ID*, the second parameter is
              the new option value. The third, optional, parameter is the
              location string as passed to Option::set. Note that the global
              value is not yet changed when the function is called. The passed
              function has to return the new value that it wants the option to
              be set to. This enables it to reject changes, or change values
              that are being set. When several change handlers are set for an
              option they are chained; the second change handler will see the
              return value of the first change handler as the "new value".
   

   :priority: The priority of the function that was added; functions with higher
             priority are called first, functions with the same priority are
             called in the order in which they were added.
   

   :returns: true when the change handler was set, false when an error occurred.
   
   .. bro:see:: Option::set


