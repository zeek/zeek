.. zeek:type:: ZeexygenTest::TypeAlias

   :Type: :zeek:type:`bool`

   This is just an alias for a builtin type ``bool``.

.. zeek:type:: ZeexygenTest::NotTypeAlias

   :Type: :zeek:type:`bool`

   This type should get its own comments, not associated w/ TypeAlias.

.. zeek:type:: ZeexygenTest::OtherTypeAlias

   :Type: :zeek:type:`bool`

   This cross references ``bool`` in the description of its type
   instead of ``TypeAlias`` just because it seems more useful --
   one doesn't have to click through the full type alias chain to
   find out what the actual type is...

.. zeek:id:: ZeexygenTest::a

   :Type: :zeek:type:`ZeexygenTest::TypeAlias`

   But this should reference a type of ``TypeAlias``.

.. zeek:id:: ZeexygenTest::b

   :Type: :zeek:type:`ZeexygenTest::OtherTypeAlias`

   And this should reference a type of ``OtherTypeAlias``.

.. zeek:type:: ZeexygenTest::MyRecord

   :Type: :zeek:type:`record`

      f1: :zeek:type:`ZeexygenTest::TypeAlias`

      f2: :zeek:type:`ZeexygenTest::OtherTypeAlias`

      f3: :zeek:type:`bool`


