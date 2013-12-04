.. bro:type:: BroxygenTest::TypeAlias

   :Type: :bro:type:`bool`

   This is just an alias for a builtin type ``bool``.

.. bro:type:: BroxygenTest::NotTypeAlias

   :Type: :bro:type:`bool`

   This type should get its own comments, not associated w/ TypeAlias.

.. bro:type:: BroxygenTest::OtherTypeAlias

   :Type: :bro:type:`bool`

   This cross references ``bool`` in the description of its type
   instead of ``TypeAlias`` just because it seems more useful --
   one doesn't have to click through the full type alias chain to
   find out what the actual type is...

.. bro:id:: BroxygenTest::a

   :Type: :bro:type:`BroxygenTest::TypeAlias`

   But this should reference a type of ``TypeAlias``.

.. bro:id:: BroxygenTest::b

   :Type: :bro:type:`BroxygenTest::OtherTypeAlias`

   And this should reference a type of ``OtherTypeAlias``.

.. bro:type:: BroxygenTest::MyRecord

   :Type: :bro:type:`record`

      f1: :bro:type:`BroxygenTest::TypeAlias`

      f2: :bro:type:`BroxygenTest::OtherTypeAlias`

      f3: :bro:type:`bool`


