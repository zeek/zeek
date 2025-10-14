:tocdepth: 3

zeekygen/example.zeek
=====================
.. zeek:namespace:: ZeekygenExample

This is an example script that demonstrates Zeekygen-style
documentation.  It generally will make most sense when viewing
the script's raw source code and comparing to the HTML-rendered
version.

Comments in the from ``##!`` are meant to summarize the script's
purpose.  They are transferred directly into the generated
`reStructuredText <http://docutils.sourceforge.net/rst.html>`_
(reST) document associated with the script.

.. tip:: You can embed directives and roles within ``##``-stylized comments.

There's also a custom role to reference any identifier node in
the Zeek Sphinx domain that's good for "see alsos", e.g.

See also: :zeek:see:`ZeekygenExample::a_var`,
:zeek:see:`ZeekygenExample::ONE`, :zeek:see:`SSH::Info`

And a custom directive does the equivalent references:

.. zeek:see:: ZeekygenExample::a_var ZeekygenExample::ONE SSH::Info

:Namespace: ZeekygenExample
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`, :doc:`policy/frameworks/software/vulnerable.zeek </scripts/policy/frameworks/software/vulnerable.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================= =======================================================
:zeek:id:`ZeekygenExample::an_option`: :zeek:type:`set` :zeek:attr:`&redef`             Add documentation for "an_option" here.
:zeek:id:`ZeekygenExample::option_with_init`: :zeek:type:`interval` :zeek:attr:`&redef` Default initialization will be generated automatically.
======================================================================================= =======================================================

State Variables
###############
========================================================================== ========================================================================
:zeek:id:`ZeekygenExample::a_var`: :zeek:type:`bool`                       Put some documentation for "a_var" here.
:zeek:id:`ZeekygenExample::summary_test`: :zeek:type:`string`              The first sentence for a particular identifier's summary text ends here.
:zeek:id:`ZeekygenExample::var_without_explicit_type`: :zeek:type:`string` Types are inferred, that information is self-documenting.
========================================================================== ========================================================================

Types
#####
==================================================================================== ===========================================================
:zeek:type:`ZeekygenExample::ComplexRecord`: :zeek:type:`record` :zeek:attr:`&redef` General documentation for a type "ComplexRecord" goes here.
:zeek:type:`ZeekygenExample::Info`: :zeek:type:`record`                              An example record to be used with a logging stream.
:zeek:type:`ZeekygenExample::SimpleEnum`: :zeek:type:`enum`                          Documentation for the "SimpleEnum" type goes here.
:zeek:type:`ZeekygenExample::SimpleRecord`: :zeek:type:`record`                      General documentation for a type "SimpleRecord" goes here.
==================================================================================== ===========================================================

Redefinitions
#############
=============================================================== =====================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                         
                                                                
                                                                * :zeek:enum:`ZeekygenExample::LOG`
:zeek:type:`Notice::Type`: :zeek:type:`enum`                    
                                                                
                                                                * :zeek:enum:`ZeekygenExample::Zeekygen_Four`:
                                                                  Omitting comments is fine, and so is mixing ``##`` and ``##<``, but
                                                                  it's probably best to use only one style consistently.
                                                                
                                                                * :zeek:enum:`ZeekygenExample::Zeekygen_One`:
                                                                  Any number of this type of comment
                                                                  will document "Zeekygen_One".
                                                                
                                                                * :zeek:enum:`ZeekygenExample::Zeekygen_Three`
                                                                
                                                                * :zeek:enum:`ZeekygenExample::Zeekygen_Two`:
                                                                  Any number of this type of comment
                                                                  will document "ZEEKYGEN_TWO".
:zeek:type:`ZeekygenExample::SimpleEnum`: :zeek:type:`enum`     Document the "SimpleEnum" redef here with any special info regarding
                                                                the *redef* itself.
                                                                
                                                                * :zeek:enum:`ZeekygenExample::FIVE`:
                                                                  Also "FIVE".
                                                                
                                                                * :zeek:enum:`ZeekygenExample::FOUR`:
                                                                  And some documentation for "FOUR".
:zeek:type:`ZeekygenExample::SimpleRecord`: :zeek:type:`record` Document the record extension *redef* itself here.
                                                                
                                                                :New Fields: :zeek:type:`ZeekygenExample::SimpleRecord`
                                                                
                                                                  field_ext: :zeek:type:`string` :zeek:attr:`&optional`
                                                                    Document the extending field like this.
=============================================================== =====================================================================

Events
######
======================================================== ==========================
:zeek:id:`ZeekygenExample::an_event`: :zeek:type:`event` Summarize "an_event" here.
======================================================== ==========================

Functions
#########
============================================================= =======================================
:zeek:id:`ZeekygenExample::a_function`: :zeek:type:`function` Summarize purpose of "a_function" here.
============================================================= =======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: ZeekygenExample::an_option
   :source-code: zeekygen/example.zeek 132 132

   :Type: :zeek:type:`set` [:zeek:type:`addr`, :zeek:type:`addr`, :zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Add documentation for "an_option" here.
   The type/attribute information is all generated automatically.

.. zeek:id:: ZeekygenExample::option_with_init
   :source-code: zeekygen/example.zeek 135 135

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 msecs``

   Default initialization will be generated automatically.
   More docs can be added here.

State Variables
###############
.. zeek:id:: ZeekygenExample::a_var
   :source-code: zeekygen/example.zeek 140 140

   :Type: :zeek:type:`bool`

   Put some documentation for "a_var" here.  Any global/non-const that
   isn't a function/event/hook is classified as a "state variable"
   in the generated docs.

.. zeek:id:: ZeekygenExample::summary_test
   :source-code: zeekygen/example.zeek 148 148

   :Type: :zeek:type:`string`

   The first sentence for a particular identifier's summary text ends here.
   And this second sentence doesn't show in the short description provided
   by the table of all identifiers declared by this script.

.. zeek:id:: ZeekygenExample::var_without_explicit_type
   :source-code: zeekygen/example.zeek 143 143

   :Type: :zeek:type:`string`
   :Default: ``"this works"``

   Types are inferred, that information is self-documenting.

Types
#####
.. zeek:type:: ZeekygenExample::ComplexRecord
   :source-code: zeekygen/example.zeek 110 117

   :Type: :zeek:type:`record`

      field1: :zeek:type:`count`
         Counts something.

      field2: :zeek:type:`bool`
         Toggles something.

      field3: :zeek:type:`ZeekygenExample::SimpleRecord`
         Zeekygen automatically tracks types
         and cross-references are automatically
         inserted into generated docs.

      msg: :zeek:type:`string` :zeek:attr:`&default` = ``"blah"`` :zeek:attr:`&optional`
         Attributes are self-documenting.
   :Attributes: :zeek:attr:`&redef`

   General documentation for a type "ComplexRecord" goes here.

.. zeek:type:: ZeekygenExample::Info
   :source-code: zeekygen/example.zeek 124 128

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`

      uid: :zeek:type:`string` :zeek:attr:`&log`

      status: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

   An example record to be used with a logging stream.
   Nothing special about it.  If another script redefs this type
   to add fields, the generated documentation will show all original
   fields plus the extensions and the scripts which contributed to it
   (provided they are also @load'ed).

.. zeek:type:: ZeekygenExample::SimpleEnum
   :source-code: zeekygen/example.zeek 78 85

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ZeekygenExample::ONE ZeekygenExample::SimpleEnum

         Documentation for particular enum values is added like this.
         And can also span multiple lines.

      .. zeek:enum:: ZeekygenExample::TWO ZeekygenExample::SimpleEnum

         Or this style is valid to document the preceding enum value.

      .. zeek:enum:: ZeekygenExample::THREE ZeekygenExample::SimpleEnum

      .. zeek:enum:: ZeekygenExample::FOUR ZeekygenExample::SimpleEnum

         And some documentation for "FOUR".

      .. zeek:enum:: ZeekygenExample::FIVE ZeekygenExample::SimpleEnum

         Also "FIVE".

   Documentation for the "SimpleEnum" type goes here.
   It can span multiple lines.

.. zeek:type:: ZeekygenExample::SimpleRecord
   :source-code: zeekygen/example.zeek 97 101

   :Type: :zeek:type:`record`

      field1: :zeek:type:`count`
         Counts something.

      field2: :zeek:type:`bool`
         Toggles something.

      field_ext: :zeek:type:`string` :zeek:attr:`&optional`
         Document the extending field like this.
         Or here, like this.

   General documentation for a type "SimpleRecord" goes here.
   The way fields can be documented is similar to what's already seen
   for enums.

Events
######
.. zeek:id:: ZeekygenExample::an_event
   :source-code: zeekygen/example.zeek 171 171

   :Type: :zeek:type:`event` (name: :zeek:type:`string`)

   Summarize "an_event" here.
   Give more details about "an_event" here.
   
   ZeekygenExample::a_function should not be confused as a parameter
   in the generated docs, but it also doesn't generate a cross-reference
   link.  Use the see role instead: :zeek:see:`ZeekygenExample::a_function`.
   

   :param name: Describe the argument here.

Functions
#########
.. zeek:id:: ZeekygenExample::a_function
   :source-code: zeekygen/example.zeek 161 161

   :Type: :zeek:type:`function` (tag: :zeek:type:`string`, msg: :zeek:type:`string`) : :zeek:type:`string`

   Summarize purpose of "a_function" here.
   Give more details about "a_function" here.
   Separating the documentation of the params/return values with
   empty comments is optional, but improves readability of script.
   

   :param tag: Function arguments can be described
        like this.
   

   :param msg: Another param.
   

   :returns: Describe the return type here.


