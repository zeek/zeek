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
============================================================ ===================================================================
:zeek:id:`bloomfilter_add`: :zeek:type:`function`            Adds an element to a Bloom filter.
:zeek:id:`bloomfilter_basic_init`: :zeek:type:`function`     Creates a basic Bloom filter.
:zeek:id:`bloomfilter_basic_init2`: :zeek:type:`function`    Creates a basic Bloom filter.
:zeek:id:`bloomfilter_clear`: :zeek:type:`function`          Removes all elements from a Bloom filter.
:zeek:id:`bloomfilter_counting_init`: :zeek:type:`function`  Creates a counting Bloom filter.
:zeek:id:`bloomfilter_internal_state`: :zeek:type:`function` Returns a string with a representation of a Bloom filter's internal
                                                             state.
:zeek:id:`bloomfilter_lookup`: :zeek:type:`function`         Retrieves the counter for a given element in a Bloom filter.
:zeek:id:`bloomfilter_merge`: :zeek:type:`function`          Merges two Bloom filters.
============================================================ ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: bloomfilter_add

   :Type: :zeek:type:`function` (bf: :zeek:type:`opaque` of bloomfilter, x: :zeek:type:`any`) : :zeek:type:`any`

   Adds an element to a Bloom filter.
   

   :bf: The Bloom filter handle.
   

   :x: The element to add.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2 
      bloomfilter_counting_init bloomfilter_lookup bloomfilter_clear 
      bloomfilter_merge

.. zeek:id:: bloomfilter_basic_init

   :Type: :zeek:type:`function` (fp: :zeek:type:`double`, capacity: :zeek:type:`count`, name: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of bloomfilter

   Creates a basic Bloom filter.
   

   :fp: The desired false-positive rate.
   

   :capacity: the maximum number of elements that guarantees a false-positive
             rate of *fp*.
   

   :name: A name that uniquely identifies and seeds the Bloom filter. If empty,
         the filter will use :zeek:id:`global_hash_seed` if that's set, and
         otherwise use a local seed tied to the current Bro process. Only
         filters with the same seed can be merged with
         :zeek:id:`bloomfilter_merge`.
   

   :returns: A Bloom filter handle.
   
   .. zeek:see:: bloomfilter_basic_init2 bloomfilter_counting_init bloomfilter_add
      bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed

.. zeek:id:: bloomfilter_basic_init2

   :Type: :zeek:type:`function` (k: :zeek:type:`count`, cells: :zeek:type:`count`, name: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of bloomfilter

   Creates a basic Bloom filter. This function serves as a low-level
   alternative to :zeek:id:`bloomfilter_basic_init` where the user has full
   control over the number of hash functions and cells in the underlying bit
   vector.
   

   :k: The number of hash functions to use.
   

   :cells: The number of cells of the underlying bit vector.
   

   :name: A name that uniquely identifies and seeds the Bloom filter. If empty,
         the filter will use :zeek:id:`global_hash_seed` if that's set, and
         otherwise use a local seed tied to the current Bro process. Only
         filters with the same seed can be merged with
         :zeek:id:`bloomfilter_merge`.
   

   :returns: A Bloom filter handle.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_counting_init  bloomfilter_add
      bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed

.. zeek:id:: bloomfilter_clear

   :Type: :zeek:type:`function` (bf: :zeek:type:`opaque` of bloomfilter) : :zeek:type:`any`

   Removes all elements from a Bloom filter. This function resets all bits in
   the underlying bitvector back to 0 but does not change the parameterization
   of the Bloom filter, such as the element type and the hasher seed.
   

   :bf: The Bloom filter handle.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_add bloomfilter_lookup
      bloomfilter_merge

.. zeek:id:: bloomfilter_counting_init

   :Type: :zeek:type:`function` (k: :zeek:type:`count`, cells: :zeek:type:`count`, max: :zeek:type:`count`, name: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of bloomfilter

   Creates a counting Bloom filter.
   

   :k: The number of hash functions to use.
   

   :cells: The number of cells of the underlying counter vector. As there's
          no single answer to what's the best parameterization for a
          counting Bloom filter, we refer to the Bloom filter literature
          here for choosing an appropiate value.
   

   :max: The maximum counter value associated with each element
        described by *w = ceil(log_2(max))* bits. Each bit in the underlying
        counter vector becomes a cell of size *w* bits.
   

   :name: A name that uniquely identifies and seeds the Bloom filter. If empty,
         the filter will use :zeek:id:`global_hash_seed` if that's set, and
         otherwise use a local seed tied to the current Bro process. Only
         filters with the same seed can be merged with
         :zeek:id:`bloomfilter_merge`.
   

   :returns: A Bloom filter handle.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2 bloomfilter_add
      bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed

.. zeek:id:: bloomfilter_internal_state

   :Type: :zeek:type:`function` (bf: :zeek:type:`opaque` of bloomfilter) : :zeek:type:`string`

   Returns a string with a representation of a Bloom filter's internal
   state. This is for debugging/testing purposes only.
   

   :bf: The Bloom filter handle.
   

   :returns: a string with a representation of a Bloom filter's internal state.

.. zeek:id:: bloomfilter_lookup

   :Type: :zeek:type:`function` (bf: :zeek:type:`opaque` of bloomfilter, x: :zeek:type:`any`) : :zeek:type:`count`

   Retrieves the counter for a given element in a Bloom filter.
   

   :bf: The Bloom filter handle.
   

   :x: The element to count.
   

   :returns: the counter associated with *x* in *bf*.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_add bloomfilter_clear
      bloomfilter_merge

.. zeek:id:: bloomfilter_merge

   :Type: :zeek:type:`function` (bf1: :zeek:type:`opaque` of bloomfilter, bf2: :zeek:type:`opaque` of bloomfilter) : :zeek:type:`opaque` of bloomfilter

   Merges two Bloom filters.
   
   .. note:: Currently Bloom filters created by different Bro instances cannot
      be merged. In the future, this will be supported as long as both filters
      are created with the same name.
   

   :bf1: The first Bloom filter handle.
   

   :bf2: The second Bloom filter handle.
   

   :returns: The union of *bf1* and *bf2*.
   
   .. zeek:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_add bloomfilter_lookup
      bloomfilter_clear


