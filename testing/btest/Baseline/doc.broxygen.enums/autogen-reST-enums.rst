.. bro:type:: TestEnum1

   :Type: :bro:type:`enum`

      .. bro:enum:: ONE TestEnum1

         like this

      .. bro:enum:: TWO TestEnum1

         or like this

      .. bro:enum:: THREE TestEnum1

         multiple
         comments
         and even
         more comments

      .. bro:enum:: FOUR TestEnum1

         adding another
         value

      .. bro:enum:: FIVE TestEnum1

         adding another
         value

   There's tons of ways an enum can look...

.. bro:type:: TestEnum2

   :Type: :bro:type:`enum`

      .. bro:enum:: A TestEnum2

         like this

      .. bro:enum:: B TestEnum2

         or like this

      .. bro:enum:: C TestEnum2

         multiple
         comments
         and even
         more comments

   The final comma is optional

.. bro:id:: TestEnumVal

   :Type: :bro:type:`TestEnum1`
   :Attributes: :bro:attr:`&redef`
   :Default: ``ONE``

   this should reference the TestEnum1 type and not a generic "enum" type

