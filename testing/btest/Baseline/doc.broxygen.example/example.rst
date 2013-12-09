:tocdepth: 3

broxygen/example.bro
====================
.. bro:namespace:: BroxygenExample

This is an example script that demonstrates Broxygen-style
documentation.  It generally will make most sense when viewing
the script's raw source code and comparing to the HTML-rendered
version.

Comments in the from ``##!`` are meant to summarize the script's
purpose.  They are transferred directly in to the generated
`reStructuredText <http://docutils.sourceforge.net/rst.html>`_
(reST) document associated with the script.

.. tip:: You can embed directives and roles within ``##``-stylized comments.

There's also a custom role to reference any identifier node in
the Bro Sphinx domain that's good for "see alsos", e.g.

See also: :bro:see:`BroxygenExample::a_var`,
:bro:see:`BroxygenExample::ONE`, :bro:see:`SSH::Info`

And a custom directive does the equivalent references:

.. bro:see:: BroxygenExample::a_var BroxygenExample::ONE SSH::Info

:Namespace: BroxygenExample
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`, :doc:`policy/frameworks/software/vulnerable.bro </scripts/policy/frameworks/software/vulnerable.bro>`
:Source File: :download:`/scripts/broxygen/example.bro`

Summary
~~~~~~~
Options
#######
==================================================================================== =======================================================
:bro:id:`BroxygenExample::an_option`: :bro:type:`set` :bro:attr:`&redef`             Add documentation for "an_option" here.
:bro:id:`BroxygenExample::option_with_init`: :bro:type:`interval` :bro:attr:`&redef` Default initialization will be generated automatically.
==================================================================================== =======================================================

State Variables
###############
======================================================================== ========================================================================
:bro:id:`BroxygenExample::a_var`: :bro:type:`bool`                       Put some documentation for "a_var" here.
:bro:id:`BroxygenExample::summary_test`: :bro:type:`string`              The first sentence for a particular identifier's summary text ends here.
:bro:id:`BroxygenExample::var_without_explicit_type`: :bro:type:`string` Types are inferred, that information is self-documenting.
======================================================================== ========================================================================

Types
#####
================================================================================= ===========================================================
:bro:type:`BroxygenExample::ComplexRecord`: :bro:type:`record` :bro:attr:`&redef` General documentation for a type "ComplexRecord" goes here.
:bro:type:`BroxygenExample::Info`: :bro:type:`record`                             An example record to be used with a logging stream.
:bro:type:`BroxygenExample::SimpleEnum`: :bro:type:`enum`                         Documentation for the "SimpleEnum" type goes here.
:bro:type:`BroxygenExample::SimpleRecord`: :bro:type:`record`                     General documentation for a type "SimpleRecord" goes here.
================================================================================= ===========================================================

Redefinitions
#############
============================================================= ====================================================================
:bro:type:`BroxygenExample::SimpleEnum`: :bro:type:`enum`     Document the "SimpleEnum" redef here with any special info regarding
                                                              the *redef* itself.
:bro:type:`BroxygenExample::SimpleRecord`: :bro:type:`record` Document the record extension *redef* itself here.
:bro:type:`Log::ID`: :bro:type:`enum`                         
:bro:type:`Notice::Type`: :bro:type:`enum`                    
============================================================= ====================================================================

Events
######
====================================================== ==========================
:bro:id:`BroxygenExample::an_event`: :bro:type:`event` Summarize "an_event" here.
====================================================== ==========================

Functions
#########
=========================================================== =======================================
:bro:id:`BroxygenExample::a_function`: :bro:type:`function` Summarize purpose of "a_function" here.
=========================================================== =======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Options
#######
.. bro:id:: BroxygenExample::an_option

   :Type: :bro:type:`set` [:bro:type:`addr`, :bro:type:`addr`, :bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Add documentation for "an_option" here.
   The type/attribute information is all generated automatically.

.. bro:id:: BroxygenExample::option_with_init

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 msecs``

   Default initialization will be generated automatically.
   More docs can be added here.

State Variables
###############
.. bro:id:: BroxygenExample::a_var

   :Type: :bro:type:`bool`

   Put some documentation for "a_var" here.  Any global/non-const that
   isn't a function/event/hook is classified as a "state variable"
   in the generated docs.

.. bro:id:: BroxygenExample::summary_test

   :Type: :bro:type:`string`

   The first sentence for a particular identifier's summary text ends here.
   And this second sentence doesn't show in the short description provided
   by the table of all identifiers declared by this script.

.. bro:id:: BroxygenExample::var_without_explicit_type

   :Type: :bro:type:`string`
   :Default: ``"this works"``

   Types are inferred, that information is self-documenting.

Types
#####
.. bro:type:: BroxygenExample::ComplexRecord

   :Type: :bro:type:`record`

      field1: :bro:type:`count`
         Counts something.

      field2: :bro:type:`bool`
         Toggles something.

      field3: :bro:type:`BroxygenExample::SimpleRecord`
         Broxygen automatically tracks types
         and cross-references are automatically
         inserted in to generated docs.

      msg: :bro:type:`string` :bro:attr:`&default` = ``"blah"`` :bro:attr:`&optional`
         Attributes are self-documenting.
   :Attributes: :bro:attr:`&redef`

   General documentation for a type "ComplexRecord" goes here.

.. bro:type:: BroxygenExample::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`

      uid: :bro:type:`string` :bro:attr:`&log`

      status: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`

   An example record to be used with a logging stream.
   Nothing special about it.  If another script redefs this type
   to add fields, the generated documentation will show all original
   fields plus the extensions and the scripts which contributed to it
   (provided they are also @load'ed).

.. bro:type:: BroxygenExample::SimpleEnum

   :Type: :bro:type:`enum`

      .. bro:enum:: BroxygenExample::ONE BroxygenExample::SimpleEnum

         Documentation for particular enum values is added like this.
         And can also span multiple lines.

      .. bro:enum:: BroxygenExample::TWO BroxygenExample::SimpleEnum

         Or this style is valid to document the preceding enum value.

      .. bro:enum:: BroxygenExample::THREE BroxygenExample::SimpleEnum

      .. bro:enum:: BroxygenExample::FOUR BroxygenExample::SimpleEnum

         And some documentation for "FOUR".

      .. bro:enum:: BroxygenExample::FIVE BroxygenExample::SimpleEnum

         Also "FIVE".

   Documentation for the "SimpleEnum" type goes here.
   It can span multiple lines.

.. bro:type:: BroxygenExample::SimpleRecord

   :Type: :bro:type:`record`

      field1: :bro:type:`count`
         Counts something.

      field2: :bro:type:`bool`
         Toggles something.

      field_ext: :bro:type:`string` :bro:attr:`&optional`
         Document the extending field like this.
         Or here, like this.

   General documentation for a type "SimpleRecord" goes here.
   The way fields can be documented is similar to what's already seen
   for enums.

Events
######
.. bro:id:: BroxygenExample::an_event

   :Type: :bro:type:`event` (name: :bro:type:`string`)

   Summarize "an_event" here.
   Give more details about "an_event" here.
   
   BroxygenExample::a_function should not be confused as a parameter
   in the generated docs, but it also doesn't generate a cross-reference
   link.  Use the see role instead: :bro:see:`BroxygenExample::a_function`.
   

   :name: Describe the argument here.

Functions
#########
.. bro:id:: BroxygenExample::a_function

   :Type: :bro:type:`function` (tag: :bro:type:`string`, msg: :bro:type:`string`) : :bro:type:`string`

   Summarize purpose of "a_function" here.
   Give more details about "a_function" here.
   Separating the documentation of the params/return values with
   empty comments is optional, but improves readability of script.
   

   :tag: Function arguments can be described
        like this.
   

   :msg: Another param.
   

   :returns: Describe the return type here.


