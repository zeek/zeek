:tocdepth: 3

base/bif/bloom-filter.bif.zeek
==============================
.. zeek:namespace:: GLOBAL

Functions to create and manipulate Bloom filters.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
============================================================ ============================================================================================
:zeek:id:`bloomfilter_add`: :zeek:type:`function`            Adds an element to a Bloom filter.
:zeek:id:`bloomfilter_basic_init`: :zeek:type:`function`     Creates a basic Bloom filter.
:zeek:id:`bloomfilter_basic_init2`: :zeek:type:`function`    Creates a basic Bloom filter.
:zeek:id:`bloomfilter_clear`: :zeek:type:`function`          Removes all elements from a Bloom filter.
:zeek:id:`bloomfilter_counting_init`: :zeek:type:`function`  Creates a counting Bloom filter.
:zeek:id:`bloomfilter_decrement`: :zeek:type:`function`      Decrements the counter for an element that was added to a counting bloom filter in the past.
:zeek:id:`bloomfilter_internal_state`: :zeek:type:`function` Returns a string with a representation of a Bloom filter's internal
                                                             state.
:zeek:id:`bloomfilter_intersect`: :zeek:type:`function`      Intersects two Bloom filters.
:zeek:id:`bloomfilter_lookup`: :zeek:type:`function`         Retrieves the counter for a given element in a Bloom filter.
:zeek:id:`bloomfilter_merge`: :zeek:type:`function`          Merges two Bloom filters.
============================================================ ============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: bloomfilter_add
   :source-code: base/bif/bloom-filter.bif.zeek 88 88

   :Type: :zeek:type:`function` (bf: :zeek:type:`opaque` of bloomfilter, x: :zeek:type:`any`) : :zeek:type:`any`

   Adds an element to a Bloom filter. For counting bloom filters, the counter is incremented.
   

   :param bf: The Bloom filter handle.
   

   :param x: The element to add.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_lookup bloomfilter_clear
      bloomfilter_merge bloomfilter_decrement

.. zeek:id:: bloomfilter_basic_init
   :source-code: base/bif/bloom-filter.bif.zeek 28 28

   :Type: :zeek:type:`function` (fp: :zeek:type:`double`, capacity: :zeek:type:`count`, name: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of bloomfilter

   Creates a basic Bloom filter.
   

   :param fp: The desired false-positive rate.
   

   :param capacity: the maximum number of elements that guarantees a false-positive
             rate of *fp*.
   

   :param name: A name that uniquely identifies and seeds the Bloom filter. If empty,
         the filter will use :zeek:id:`global_hash_seed` if that's set, and
         otherwise use a local seed tied to the current Zeek process. Only
         filters with the same seed can be merged with
         :zeek:id:`bloomfilter_merge`.
   

   :returns: A Bloom filter handle.
   
   .. zeek:see:: bloomfilter_basic_init2 bloomfilter_counting_init bloomfilter_add
      bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed

.. zeek:id:: bloomfilter_basic_init2
   :source-code: base/bif/bloom-filter.bif.zeek 50 50

   :Type: :zeek:type:`function` (k: :zeek:type:`count`, cells: :zeek:type:`count`, name: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of bloomfilter

   Creates a basic Bloom filter. This function serves as a low-level
   alternative to :zeek:id:`bloomfilter_basic_init` where the user has full
   control over the number of hash functions and cells in the underlying bit
   vector.
   

   :param k: The number of hash functions to use.
   

   :param cells: The number of cells of the underlying bit vector.
   

   :param name: A name that uniquely identifies and seeds the Bloom filter. If empty,
         the filter will use :zeek:id:`global_hash_seed` if that's set, and
         otherwise use a local seed tied to the current Zeek process. Only
         filters with the same seed can be merged with
         :zeek:id:`bloomfilter_merge`.
   

   :returns: A Bloom filter handle.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_counting_init  bloomfilter_add
      bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed

.. zeek:id:: bloomfilter_clear
   :source-code: base/bif/bloom-filter.bif.zeek 137 137

   :Type: :zeek:type:`function` (bf: :zeek:type:`opaque` of bloomfilter) : :zeek:type:`any`

   Removes all elements from a Bloom filter. This function resets all bits in
   the underlying bitvector back to 0 but does not change the parameterization
   of the Bloom filter, such as the element type and the hasher seed.
   

   :param bf: The Bloom filter handle.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_add bloomfilter_lookup
      bloomfilter_merge

.. zeek:id:: bloomfilter_counting_init
   :source-code: base/bif/bloom-filter.bif.zeek 76 76

   :Type: :zeek:type:`function` (k: :zeek:type:`count`, cells: :zeek:type:`count`, max: :zeek:type:`count`, name: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of bloomfilter

   Creates a counting Bloom filter.
   

   :param k: The number of hash functions to use.
   

   :param cells: The number of cells of the underlying counter vector. As there's
          no single answer to what's the best parameterization for a
          counting Bloom filter, we refer to the Bloom filter literature
          here for choosing an appropriate value.
   

   :param max: The maximum counter value associated with each element
        described by *w = ceil(log_2(max))* bits. Each bit in the underlying
        counter vector becomes a cell of size *w* bits.
   

   :param name: A name that uniquely identifies and seeds the Bloom filter. If empty,
         the filter will use :zeek:id:`global_hash_seed` if that's set, and
         otherwise use a local seed tied to the current Zeek process. Only
         filters with the same seed can be merged with
         :zeek:id:`bloomfilter_merge`.
   

   :returns: A Bloom filter handle.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2 bloomfilter_add
      bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed

.. zeek:id:: bloomfilter_decrement
   :source-code: base/bif/bloom-filter.bif.zeek 105 105

   :Type: :zeek:type:`function` (bf: :zeek:type:`opaque` of bloomfilter, x: :zeek:type:`any`) : :zeek:type:`bool`

   Decrements the counter for an element that was added to a counting bloom filter in the past.
   
   Note that decrement operations can lead to false negatives if used on a counting bloom-filter
   that exceeded the width of its counter.
   

   :param bf: The counting bloom filter handle.
   

   :param x: The element to decrement
   

   :returns: True on success
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_lookup bloomfilter_clear
      bloomfilter_merge

.. zeek:id:: bloomfilter_internal_state
   :source-code: base/bif/bloom-filter.bif.zeek 185 185

   :Type: :zeek:type:`function` (bf: :zeek:type:`opaque` of bloomfilter) : :zeek:type:`string`

   Returns a string with a representation of a Bloom filter's internal
   state. This is for debugging/testing purposes only.
   

   :param bf: The Bloom filter handle.
   

   :returns: a string with a representation of a Bloom filter's internal state.

.. zeek:id:: bloomfilter_intersect
   :source-code: base/bif/bloom-filter.bif.zeek 176 176

   :Type: :zeek:type:`function` (bf1: :zeek:type:`opaque` of bloomfilter, bf2: :zeek:type:`opaque` of bloomfilter) : :zeek:type:`opaque` of bloomfilter

   Intersects two Bloom filters.
   
   The resulting Bloom filter returns true when queried for elements
   that were contained in both bloom filters. Note that intersected Bloom
   filters have a slightly higher probability of false positives than
   Bloom filters created from scratch.
   
   Please note that, while this function works with basic and with counting
   bloom filters, the result always is a basic bloom filter. So - intersecting
   two counting bloom filters will result in a basic bloom filter. The reason
   for this is that there is no reasonable definition of how to handle counters
   during intersection.
   

   :param bf1: The first Bloom filter handle.
   

   :param bf2: The second Bloom filter handle.
   

   :returns: The intersection of *bf1* and *bf2*.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_add bloomfilter_lookup
      bloomfilter_clear bloomfilter_merge

.. zeek:id:: bloomfilter_lookup
   :source-code: base/bif/bloom-filter.bif.zeek 125 125

   :Type: :zeek:type:`function` (bf: :zeek:type:`opaque` of bloomfilter, x: :zeek:type:`any`) : :zeek:type:`count`

   Retrieves the counter for a given element in a Bloom filter.
   
   For a basic bloom filter, this is 0 when the element is not part of the bloom filter, or 1
   if it is part of the bloom filter.
   
   For a counting bloom filter, this is the estimate of how often an element was added.
   

   :param bf: The Bloom filter handle.
   

   :param x: The element to count.
   

   :returns: the counter associated with *x* in *bf*.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_add bloomfilter_clear
      bloomfilter_merge

.. zeek:id:: bloomfilter_merge
   :source-code: base/bif/bloom-filter.bif.zeek 151 151

   :Type: :zeek:type:`function` (bf1: :zeek:type:`opaque` of bloomfilter, bf2: :zeek:type:`opaque` of bloomfilter) : :zeek:type:`opaque` of bloomfilter

   Merges two Bloom filters.
   

   :param bf1: The first Bloom filter handle.
   

   :param bf2: The second Bloom filter handle.
   

   :returns: The union of *bf1* and *bf2*.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_add bloomfilter_lookup
      bloomfilter_clear bloomfilter_merge


