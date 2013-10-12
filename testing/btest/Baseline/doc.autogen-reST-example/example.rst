.. Automatically generated.  Do not edit.

:tocdepth: 3

example.bro
===========
.. bro:namespace:: Example

This is an example script that demonstrates documentation features.
Comments of the form ``##!`` are for the script summary.  The contents of
these comments are transferred directly into the auto-generated
`reStructuredText <http://docutils.sourceforge.net/rst.html>`_
(reST) document's summary section.

.. tip:: You can embed directives and roles within ``##``-stylized comments.

There's also a custom role to reference any identifier node in
the Bro Sphinx domain that's good for "see alsos", e.g.

See also: :bro:see:`Example::a_var`, :bro:see:`Example::ONE`,
:bro:see:`SSH::Info`

And a custom directive does the equivalent references:

.. bro:see:: Example::a_var Example::ONE SSH::Info

:Namespace: ``Example``
:Imports: :doc:`policy/frameworks/software/vulnerable </scripts/policy/frameworks/software/vulnerable>`
:Source File: :download:`example.bro`

Summary
~~~~~~~
Options
#######
============================================================================ ======================================
:bro:id:`Example::an_option`: :bro:type:`set` :bro:attr:`&redef`             add documentation for "an_option" here

:bro:id:`Example::option_with_init`: :bro:type:`interval` :bro:attr:`&redef` More docs can be added here.
============================================================================ ======================================

State Variables
###############
=========================================================================== ==================================================
:bro:id:`Example::a_var`: :bro:type:`bool`                                  put some documentation for "a_var" here

:bro:id:`Example::var_with_attr`: :bro:type:`count` :bro:attr:`&persistent`

:bro:id:`Example::var_without_explicit_type`: :bro:type:`string`

:bro:id:`Example::dummy`: :bro:type:`string`                                The first.sentence for the summary text ends here.
=========================================================================== ==================================================

Types
#####
====================================================== ==========================================================
:bro:type:`Example::SimpleEnum`: :bro:type:`enum`      documentation for "SimpleEnum"
                                                       goes here.

:bro:type:`Example::SimpleRecord`: :bro:type:`record`  general documentation for a type "SimpleRecord"
                                                       goes here.

:bro:type:`Example::ComplexRecord`: :bro:type:`record` general documentation for a type "ComplexRecord" goes here

:bro:type:`Example::Info`: :bro:type:`record`          An example record to be used with a logging stream.
====================================================== ==========================================================

Events
######
================================================= =============================================================
:bro:id:`Example::an_event`: :bro:type:`event`    Summarize "an_event" here.

:bro:id:`Example::log_example`: :bro:type:`event` This is a declaration of an example event that can be used in
                                                  logging streams and is raised once for each log entry.
================================================= =============================================================

Functions
#########
=================================================== =======================================
:bro:id:`Example::a_function`: :bro:type:`function` Summarize purpose of "a_function" here.
=================================================== =======================================

Redefinitions
#############
===================================================== ========================================
:bro:type:`Log::ID`: :bro:type:`enum`

:bro:type:`Example::SimpleEnum`: :bro:type:`enum`     document the "SimpleEnum" redef here

:bro:type:`Example::SimpleRecord`: :bro:type:`record` document the record extension redef here
===================================================== ========================================

Notices
#######
:bro:type:`Notice::Type`

   :Type: :bro:type:`enum`

      .. bro:enum:: Example::Notice_One Notice::Type

         any number of this type of comment
         will document "Notice_One"

      .. bro:enum:: Example::Notice_Two Notice::Type

         any number of this type of comment
         will document "Notice_Two"

      .. bro:enum:: Example::Notice_Three Notice::Type

      .. bro:enum:: Example::Notice_Four Notice::Type

Configuration Changes
#####################
Packet Filter
^^^^^^^^^^^^^
Loading this script makes the following changes to :bro:see:`capture_filters`.

Filters added::

    [ssl] = tcp port 443,
    [nntps] = tcp port 562

Detailed Interface
~~~~~~~~~~~~~~~~~~
Options
#######
.. bro:id:: Example::an_option

   :Type: :bro:type:`set` [:bro:type:`addr`, :bro:type:`addr`, :bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   add documentation for "an_option" here

.. bro:id:: Example::option_with_init

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 msecs``

   More docs can be added here.

State Variables
###############
.. bro:id:: Example::a_var

   :Type: :bro:type:`bool`

   put some documentation for "a_var" here

.. bro:id:: Example::var_with_attr

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&persistent`

.. bro:id:: Example::var_without_explicit_type

   :Type: :bro:type:`string`
   :Default: ``"this works"``

.. bro:id:: Example::dummy

   :Type: :bro:type:`string`

   The first.sentence for the summary text ends here.  And this second
   sentence doesn't show in the short description.

Types
#####
.. bro:type:: Example::SimpleEnum

   :Type: :bro:type:`enum`

      .. bro:enum:: Example::ONE Example::SimpleEnum

         and more specific info for "ONE"
         can span multiple lines

      .. bro:enum:: Example::TWO Example::SimpleEnum

         or more info like this for "TWO"
         can span multiple lines

      .. bro:enum:: Example::THREE Example::SimpleEnum

   documentation for "SimpleEnum"
   goes here.

.. bro:type:: Example::SimpleRecord

   :Type: :bro:type:`record`

      field1: :bro:type:`count`
         counts something

      field2: :bro:type:`bool`
         toggles something

   general documentation for a type "SimpleRecord"
   goes here.

.. bro:type:: Example::ComplexRecord

   :Type: :bro:type:`record`

      field1: :bro:type:`count`
         counts something

      field2: :bro:type:`bool`
         toggles something

      field3: :bro:type:`Example::SimpleRecord`

      msg: :bro:type:`string` :bro:attr:`&default` = ``"blah"`` :bro:attr:`&optional`
         attributes are self-documenting

   general documentation for a type "ComplexRecord" goes here

.. bro:type:: Example::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`

      uid: :bro:type:`string` :bro:attr:`&log`

      status: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`

   An example record to be used with a logging stream.

Events
######
.. bro:id:: Example::an_event

   :Type: :bro:type:`event` (name: :bro:type:`string`)

   Summarize "an_event" here.
   Give more details about "an_event" here.
   Example::an_event should not be confused as a parameter.
   
   :param name: describe the argument here

.. bro:id:: Example::log_example

   :Type: :bro:type:`event` (rec: :bro:type:`Example::Info`)

   This is a declaration of an example event that can be used in
   logging streams and is raised once for each log entry.

Functions
#########
.. bro:id:: Example::a_function

   :Type: :bro:type:`function` (tag: :bro:type:`string`, msg: :bro:type:`string`) : :bro:type:`string`

   Summarize purpose of "a_function" here.
   Give more details about "a_function" here.
   Separating the documentation of the params/return values with
   empty comments is optional, but improves readability of script.
   
   
   :param tag: function arguments can be described
        like this
   
   :param msg: another param
   
   
   :returns: describe the return type here

Redefinitions
#############
:bro:type:`Log::ID`

   :Type: :bro:type:`enum`

      .. bro:enum:: Example::LOG Log::ID

:bro:type:`Example::SimpleEnum`

   :Type: :bro:type:`enum`

      .. bro:enum:: Example::FOUR Example::SimpleEnum

         and some documentation for "FOUR"

      .. bro:enum:: Example::FIVE Example::SimpleEnum

         also "FIVE" for good measure

   document the "SimpleEnum" redef here

:bro:type:`Example::SimpleRecord`

   :Type: :bro:type:`record`

      field_ext: :bro:type:`string` :bro:attr:`&optional`
         document the extending field here
         (or here)

   document the record extension redef here

