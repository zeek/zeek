:tocdepth: 3

base/bif/option.bif.zeek
========================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Option

Definitions of built-in functions that allow the scripting layer to
change the value of options and to be notified when option values change.

:Namespaces: GLOBAL, Option

Summary
~~~~~~~
Functions
#########
============================================================ ================================================================
:zeek:id:`Option::any_set_to_any_vec`: :zeek:type:`function` Helper function that converts a set (of arbitrary index type) to
                                                             a "vector of any".
:zeek:id:`Option::set`: :zeek:type:`function`                Set an option to a new value.
:zeek:id:`Option::set_change_handler`: :zeek:type:`function` Set a change handler for an option.
============================================================ ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Option::any_set_to_any_vec
   :source-code: base/bif/option.bif.zeek 65 65

   :Type: :zeek:type:`function` (v: :zeek:type:`any`) : :zeek:type:`any_vec`

   Helper function that converts a set (of arbitrary index type) to
   a "vector of any".
   

   :param v: an "any" type corresponding to a set.
   

   :returns: a vector-of-any with one element for each member of v.

.. zeek:id:: Option::set
   :source-code: base/bif/option.bif.zeek 29 29

   :Type: :zeek:type:`function` (ID: :zeek:type:`string`, val: :zeek:type:`any`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Set an option to a new value. This change will also cause the option change
   handlers to be called.
   

   :param ID: The ID of the option to update.
   

   :param val: The new value of the option.
   

   :param location: Optional parameter detailing where this change originated from.
   

   :returns: true on success, false when an error occurred.
   
   .. zeek:see:: Option::set_change_handler Config::set_value
   
   .. note:: :zeek:id:`Option::set` only works on one node and does not distribute
             new values across a cluster. The higher-level :zeek:id:`Config::set_value`
             supports clusterization and should typically be used instead of this
             lower-level function.

.. zeek:id:: Option::set_change_handler
   :source-code: base/bif/option.bif.zeek 56 56

   :Type: :zeek:type:`function` (ID: :zeek:type:`string`, on_change: :zeek:type:`any`, priority: :zeek:type:`int` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Set a change handler for an option. The change handler will be
   called anytime :zeek:id:`Option::set` is called for the option.
   

   :param ID: The ID of the option for which change notifications are desired.
   

   :param on_change: The function that will be called when a change occurs. The
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
   

   :param priority: The priority of the function that was added; functions with higher
             priority are called first, functions with the same priority are
             called in the order in which they were added.
   

   :returns: true when the change handler was set, false when an error occurred.
   
   .. zeek:see:: Option::set


