.. bro:type:: TestRecord1

   :Type: :bro:type:`record`

      field1: :bro:type:`bool`

      field2: :bro:type:`count`


.. bro:type:: TestRecord2

   :Type: :bro:type:`record`

      A: :bro:type:`count`
         document ``A``

      B: :bro:type:`bool`
         document ``B``

      C: :bro:type:`TestRecord1`
         and now ``C``
         is a declared type

      D: :bro:type:`set` [:bro:type:`count`, :bro:type:`bool`]
         sets/tables should show the index types

   Here's the ways records and record fields can be documented.

