:tocdepth: 3

base/frameworks/broker/data.zeek
================================
.. zeek:namespace:: Broker

The Broker-based Data API and its various options.

:Namespace: Broker
:Imports: :doc:`base/bif/data.bif.zeek </scripts/base/bif/data.bif.zeek>`, :doc:`base/frameworks/broker/main.zeek </scripts/base/frameworks/broker/main.zeek>`

Summary
~~~~~~~
Functions
#########
=============================================================== =============================================================================
:zeek:id:`Broker::data`: :zeek:type:`function`                  Convert any Zeek value to communication data.
:zeek:id:`Broker::data_type`: :zeek:type:`function`             Retrieve the type of data associated with communication data.
:zeek:id:`Broker::record_assign`: :zeek:type:`function`         Replace a field in a record at a particular position.
:zeek:id:`Broker::record_create`: :zeek:type:`function`         Create communication data of type "record".
:zeek:id:`Broker::record_iterator`: :zeek:type:`function`       Create an iterator for a record.
:zeek:id:`Broker::record_iterator_last`: :zeek:type:`function`  Check if there are no more elements to iterate over.
:zeek:id:`Broker::record_iterator_next`: :zeek:type:`function`  Advance an iterator.
:zeek:id:`Broker::record_iterator_value`: :zeek:type:`function` Retrieve the data at an iterator's current position.
:zeek:id:`Broker::record_lookup`: :zeek:type:`function`         Lookup a field in a record at a particular position.
:zeek:id:`Broker::record_size`: :zeek:type:`function`           Get the number of fields within a record.
:zeek:id:`Broker::set_clear`: :zeek:type:`function`             Remove all elements within a set.
:zeek:id:`Broker::set_contains`: :zeek:type:`function`          Check if a set contains a particular element.
:zeek:id:`Broker::set_create`: :zeek:type:`function`            Create communication data of type "set".
:zeek:id:`Broker::set_insert`: :zeek:type:`function`            Insert an element into a set.
:zeek:id:`Broker::set_iterator`: :zeek:type:`function`          Create an iterator for a set.
:zeek:id:`Broker::set_iterator_last`: :zeek:type:`function`     Check if there are no more elements to iterate over.
:zeek:id:`Broker::set_iterator_next`: :zeek:type:`function`     Advance an iterator.
:zeek:id:`Broker::set_iterator_value`: :zeek:type:`function`    Retrieve the data at an iterator's current position.
:zeek:id:`Broker::set_remove`: :zeek:type:`function`            Remove an element from a set.
:zeek:id:`Broker::set_size`: :zeek:type:`function`              Get the number of elements within a set.
:zeek:id:`Broker::table_clear`: :zeek:type:`function`           Remove all elements within a table.
:zeek:id:`Broker::table_contains`: :zeek:type:`function`        Check if a table contains a particular key.
:zeek:id:`Broker::table_create`: :zeek:type:`function`          Create communication data of type "table".
:zeek:id:`Broker::table_insert`: :zeek:type:`function`          Insert a key-value pair into a table.
:zeek:id:`Broker::table_iterator`: :zeek:type:`function`        Create an iterator for a table.
:zeek:id:`Broker::table_iterator_last`: :zeek:type:`function`   Check if there are no more elements to iterate over.
:zeek:id:`Broker::table_iterator_next`: :zeek:type:`function`   Advance an iterator.
:zeek:id:`Broker::table_iterator_value`: :zeek:type:`function`  Retrieve the data at an iterator's current position.
:zeek:id:`Broker::table_lookup`: :zeek:type:`function`          Retrieve a value from a table.
:zeek:id:`Broker::table_remove`: :zeek:type:`function`          Remove a key-value pair from a table.
:zeek:id:`Broker::table_size`: :zeek:type:`function`            Get the number of elements within a table.
:zeek:id:`Broker::vector_clear`: :zeek:type:`function`          Remove all elements within a vector.
:zeek:id:`Broker::vector_create`: :zeek:type:`function`         Create communication data of type "vector".
:zeek:id:`Broker::vector_insert`: :zeek:type:`function`         Insert an element into a vector at a particular position, possibly displacing
                                                                existing elements (insertion always grows the size of the vector by one).
:zeek:id:`Broker::vector_iterator`: :zeek:type:`function`       Create an iterator for a vector.
:zeek:id:`Broker::vector_iterator_last`: :zeek:type:`function`  Check if there are no more elements to iterate over.
:zeek:id:`Broker::vector_iterator_next`: :zeek:type:`function`  Advance an iterator.
:zeek:id:`Broker::vector_iterator_value`: :zeek:type:`function` Retrieve the data at an iterator's current position.
:zeek:id:`Broker::vector_lookup`: :zeek:type:`function`         Lookup an element in a vector at a particular position.
:zeek:id:`Broker::vector_remove`: :zeek:type:`function`         Remove an element from a vector at a particular position.
:zeek:id:`Broker::vector_replace`: :zeek:type:`function`        Replace an element in a vector at a particular position.
:zeek:id:`Broker::vector_size`: :zeek:type:`function`           Get the number of elements within a vector.
=============================================================== =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Broker::data
   :source-code: base/frameworks/broker/data.zeek 368 371

   :Type: :zeek:type:`function` (d: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Convert any Zeek value to communication data.

   .. note:: Normally you won't need to use this function as data
      conversion happens implicitly when passing Zeek values into Broker
      functions.


   :param d: any Zeek value to attempt to convert (not all types are supported).


   :returns: the converted communication data.  If the supplied Zeek data
            type does not support conversion to communication data, the
            returned record's optional field will not be set.

.. zeek:id:: Broker::data_type
   :source-code: base/frameworks/broker/data.zeek 363 366

   :Type: :zeek:type:`function` (d: :zeek:type:`Broker::Data`) : :zeek:type:`Broker::DataType`

   Retrieve the type of data associated with communication data.


   :param d: the communication data.


   :returns: The data type associated with the communication data.
            Note that Broker represents records in the same way as
            vectors, so there is no "record" type.

.. zeek:id:: Broker::record_assign
   :source-code: base/frameworks/broker/data.zeek 543 546

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`

   Replace a field in a record at a particular position.


   :param r: the record to modify.


   :param d: the new field value to assign.


   :param idx: the index to replace.


   :returns: false if the index was larger than any valid index, else true.

.. zeek:id:: Broker::record_create
   :source-code: base/frameworks/broker/data.zeek 533 536

   :Type: :zeek:type:`function` (sz: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Create communication data of type "record".


   :param sz: the number of fields in the record.


   :returns: record data, with all fields uninitialized.

.. zeek:id:: Broker::record_iterator
   :source-code: base/frameworks/broker/data.zeek 553 556

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::RecordIterator

   Create an iterator for a record.  Note that this makes a copy of the record
   internally to ensure the iterator is always valid.


   :param r: the record to iterate over.


   :returns: an iterator.

.. zeek:id:: Broker::record_iterator_last
   :source-code: base/frameworks/broker/data.zeek 558 561

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.


   :param it: an iterator.


   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::record_iterator_next
   :source-code: base/frameworks/broker/data.zeek 563 566

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`bool`

   Advance an iterator.


   :param it: an iterator.


   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::record_iterator_value
   :source-code: base/frameworks/broker/data.zeek 568 571

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::RecordIterator) : :zeek:type:`Broker::Data`

   Retrieve the data at an iterator's current position.


   :param it: an iterator.


   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::record_lookup
   :source-code: base/frameworks/broker/data.zeek 548 551

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Lookup a field in a record at a particular position.


   :param r: the record to query.


   :param idx: the index to lookup.


   :returns: the value at the index.  The optional field of the returned record
            may not be set if the field of the record has no value or if the
            index was not valid.

.. zeek:id:: Broker::record_size
   :source-code: base/frameworks/broker/data.zeek 538 541

   :Type: :zeek:type:`function` (r: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of fields within a record.


   :param r: the record to query.


   :returns: the number of fields in the record.

.. zeek:id:: Broker::set_clear
   :source-code: base/frameworks/broker/data.zeek 378 381

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`bool`

   Remove all elements within a set.


   :param s: the set to clear.


   :returns: always true.

.. zeek:id:: Broker::set_contains
   :source-code: base/frameworks/broker/data.zeek 388 391

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Check if a set contains a particular element.


   :param s: the set to query.


   :param key: the element to check for existence.


   :returns: true if the key exists in the set.

.. zeek:id:: Broker::set_create
   :source-code: base/frameworks/broker/data.zeek 373 376

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`

   Create communication data of type "set".

.. zeek:id:: Broker::set_insert
   :source-code: base/frameworks/broker/data.zeek 393 396

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Insert an element into a set.


   :param s: the set to modify.


   :param key: the element to insert.


   :returns: true if the key was inserted, or false if it already existed.

.. zeek:id:: Broker::set_iterator
   :source-code: base/frameworks/broker/data.zeek 403 406

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::SetIterator

   Create an iterator for a set.  Note that this makes a copy of the set
   internally to ensure the iterator is always valid.


   :param s: the set to iterate over.


   :returns: an iterator.

.. zeek:id:: Broker::set_iterator_last
   :source-code: base/frameworks/broker/data.zeek 408 411

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.


   :param it: an iterator.


   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::set_iterator_next
   :source-code: base/frameworks/broker/data.zeek 413 416

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`bool`

   Advance an iterator.


   :param it: an iterator.


   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::set_iterator_value
   :source-code: base/frameworks/broker/data.zeek 418 421

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::SetIterator) : :zeek:type:`Broker::Data`

   Retrieve the data at an iterator's current position.


   :param it: an iterator.


   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::set_remove
   :source-code: base/frameworks/broker/data.zeek 398 401

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Remove an element from a set.


   :param s: the set to modify.


   :param key: the element to remove.


   :returns: true if the element existed in the set and is now removed.

.. zeek:id:: Broker::set_size
   :source-code: base/frameworks/broker/data.zeek 383 386

   :Type: :zeek:type:`function` (s: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of elements within a set.


   :param s: the set to query.


   :returns: the number of elements in the set.

.. zeek:id:: Broker::table_clear
   :source-code: base/frameworks/broker/data.zeek 428 431

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`bool`

   Remove all elements within a table.


   :param t: the table to clear.


   :returns: always true.

.. zeek:id:: Broker::table_contains
   :source-code: base/frameworks/broker/data.zeek 438 441

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`bool`

   Check if a table contains a particular key.


   :param t: the table to query.


   :param key: the key to check for existence.


   :returns: true if the key exists in the table.

.. zeek:id:: Broker::table_create
   :source-code: base/frameworks/broker/data.zeek 423 426

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`

   Create communication data of type "table".

.. zeek:id:: Broker::table_insert
   :source-code: base/frameworks/broker/data.zeek 443 446

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`, val: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Insert a key-value pair into a table.


   :param t: the table to modify.


   :param key: the key at which to insert the value.


   :param val: the value to insert.


   :returns: true if the key-value pair was inserted, or false if the key
            already existed in the table.

.. zeek:id:: Broker::table_iterator
   :source-code: base/frameworks/broker/data.zeek 458 461

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::TableIterator

   Create an iterator for a table.  Note that this makes a copy of the table
   internally to ensure the iterator is always valid.


   :param t: the table to iterate over.


   :returns: an iterator.

.. zeek:id:: Broker::table_iterator_last
   :source-code: base/frameworks/broker/data.zeek 463 466

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.


   :param it: an iterator.


   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::table_iterator_next
   :source-code: base/frameworks/broker/data.zeek 468 471

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`bool`

   Advance an iterator.


   :param it: an iterator.


   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::table_iterator_value
   :source-code: base/frameworks/broker/data.zeek 473 476

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::TableIterator) : :zeek:type:`Broker::TableItem`

   Retrieve the data at an iterator's current position.


   :param it: an iterator.


   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::table_lookup
   :source-code: base/frameworks/broker/data.zeek 453 456

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Retrieve a value from a table.


   :param t: the table to query.


   :param key: the key to lookup.


   :returns: the value associated with the key.  If the key did not exist, then
            the optional field of the returned record is not set.

.. zeek:id:: Broker::table_remove
   :source-code: base/frameworks/broker/data.zeek 448 451

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`, key: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Remove a key-value pair from a table.


   :param t: the table to modify.


   :param key: the key to remove from the table.


   :returns: the value associated with the key.  If the key did not exist, then
            the optional field of the returned record is not set.

.. zeek:id:: Broker::table_size
   :source-code: base/frameworks/broker/data.zeek 433 436

   :Type: :zeek:type:`function` (t: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of elements within a table.


   :param t: the table to query.


   :returns: the number of elements in the table.

.. zeek:id:: Broker::vector_clear
   :source-code: base/frameworks/broker/data.zeek 483 486

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`bool`

   Remove all elements within a vector.


   :param v: the vector to clear.


   :returns: always true.

.. zeek:id:: Broker::vector_create
   :source-code: base/frameworks/broker/data.zeek 478 481

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::Data`

   Create communication data of type "vector".

.. zeek:id:: Broker::vector_insert
   :source-code: base/frameworks/broker/data.zeek 493 496

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`bool`

   Insert an element into a vector at a particular position, possibly displacing
   existing elements (insertion always grows the size of the vector by one).


   :param v: the vector to modify.


   :param d: the element to insert.


   :param idx: the index at which to insert the data.  If it is greater than the
        current size of the vector, the element is inserted at the end.


   :returns: always true.

.. zeek:id:: Broker::vector_iterator
   :source-code: base/frameworks/broker/data.zeek 513 516

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`opaque` of Broker::VectorIterator

   Create an iterator for a vector.  Note that this makes a copy of the vector
   internally to ensure the iterator is always valid.


   :param v: the vector to iterate over.


   :returns: an iterator.

.. zeek:id:: Broker::vector_iterator_last
   :source-code: base/frameworks/broker/data.zeek 518 521

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`

   Check if there are no more elements to iterate over.


   :param it: an iterator.


   :returns: true if there are no more elements to iterator over, i.e.
            the iterator is one-past-the-final-element.

.. zeek:id:: Broker::vector_iterator_next
   :source-code: base/frameworks/broker/data.zeek 523 526

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`bool`

   Advance an iterator.


   :param it: an iterator.


   :returns: true if the iterator, after advancing, still references an element
            in the collection.  False if the iterator, after advancing, is
            one-past-the-final-element.

.. zeek:id:: Broker::vector_iterator_value
   :source-code: base/frameworks/broker/data.zeek 528 531

   :Type: :zeek:type:`function` (it: :zeek:type:`opaque` of Broker::VectorIterator) : :zeek:type:`Broker::Data`

   Retrieve the data at an iterator's current position.


   :param it: an iterator.


   :returns: element in the collection that the iterator currently references.

.. zeek:id:: Broker::vector_lookup
   :source-code: base/frameworks/broker/data.zeek 508 511

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Lookup an element in a vector at a particular position.


   :param v: the vector to query.


   :param idx: the index to lookup.


   :returns: the value at the index.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. zeek:id:: Broker::vector_remove
   :source-code: base/frameworks/broker/data.zeek 503 506

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`) : :zeek:type:`Broker::Data`

   Remove an element from a vector at a particular position.


   :param v: the vector to modify.


   :param idx: the index to remove.


   :returns: the value that was just evicted.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. zeek:id:: Broker::vector_replace
   :source-code: base/frameworks/broker/data.zeek 498 501

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`, idx: :zeek:type:`count`, d: :zeek:type:`any`) : :zeek:type:`Broker::Data`

   Replace an element in a vector at a particular position.


   :param v: the vector to modify.


   :param d: the element to insert.


   :param idx: the index to replace.


   :returns: the value that was just evicted.  If the index was larger than any
            valid index, the optional field of the returned record is not set.

.. zeek:id:: Broker::vector_size
   :source-code: base/frameworks/broker/data.zeek 488 491

   :Type: :zeek:type:`function` (v: :zeek:type:`Broker::Data`) : :zeek:type:`count`

   Get the number of elements within a vector.


   :param v: the vector to query.


   :returns: the number of elements in the vector.


