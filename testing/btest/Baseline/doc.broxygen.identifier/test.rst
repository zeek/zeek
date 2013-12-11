.. bro:id:: BroxygenExample::Broxygen_One

   :Type: :bro:type:`Notice::Type`

   Any number of this type of comment
   will document "Broxygen_One".

.. bro:id:: BroxygenExample::Broxygen_Two

   :Type: :bro:type:`Notice::Type`

   Any number of this type of comment
   will document "BROXYGEN_TWO".

.. bro:id:: BroxygenExample::Broxygen_Three

   :Type: :bro:type:`Notice::Type`


.. bro:id:: BroxygenExample::Broxygen_Four

   :Type: :bro:type:`Notice::Type`

   Omitting comments is fine, and so is mixing ``##`` and ``##<``, but
   it's probably best to use only one style consistently.

.. bro:id:: BroxygenExample::LOG

   :Type: :bro:type:`Log::ID`


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

.. bro:id:: BroxygenExample::ONE

   :Type: :bro:type:`BroxygenExample::SimpleEnum`

   Documentation for particular enum values is added like this.
   And can also span multiple lines.

.. bro:id:: BroxygenExample::TWO

   :Type: :bro:type:`BroxygenExample::SimpleEnum`

   Or this style is valid to document the preceding enum value.

.. bro:id:: BroxygenExample::THREE

   :Type: :bro:type:`BroxygenExample::SimpleEnum`


.. bro:id:: BroxygenExample::FOUR

   :Type: :bro:type:`BroxygenExample::SimpleEnum`

   And some documentation for "FOUR".

.. bro:id:: BroxygenExample::FIVE

   :Type: :bro:type:`BroxygenExample::SimpleEnum`

   Also "FIVE".

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

.. bro:id:: BroxygenExample::a_var

   :Type: :bro:type:`bool`

   Put some documentation for "a_var" here.  Any global/non-const that
   isn't a function/event/hook is classified as a "state variable"
   in the generated docs.

.. bro:id:: BroxygenExample::var_without_explicit_type

   :Type: :bro:type:`string`
   :Default: ``"this works"``

   Types are inferred, that information is self-documenting.

.. bro:id:: BroxygenExample::summary_test

   :Type: :bro:type:`string`

   The first sentence for a particular identifier's summary text ends here.
   And this second sentence doesn't show in the short description provided
   by the table of all identifiers declared by this script.

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

.. bro:id:: BroxygenExample::an_event

   :Type: :bro:type:`event` (name: :bro:type:`string`)

   Summarize "an_event" here.
   Give more details about "an_event" here.
   
   BroxygenExample::a_function should not be confused as a parameter
   in the generated docs, but it also doesn't generate a cross-reference
   link.  Use the see role instead: :bro:see:`BroxygenExample::a_function`.
   

   :name: Describe the argument here.

.. bro:id:: BroxygenExample::function_without_proto

   :Type: :bro:type:`function` (tag: :bro:type:`string`) : :bro:type:`string`


.. bro:type:: BroxygenExample::PrivateRecord

   :Type: :bro:type:`record`

      field1: :bro:type:`bool`

      field2: :bro:type:`count`


