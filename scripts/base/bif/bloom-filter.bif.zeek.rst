:tocdepth: 3

base/bif/bloom-filter.bif.zeek
==============================
.. bro:namespace:: GLOBAL

Functions to create and manipulate Bloom filters.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================== ===================================================================
:bro:id:`bloomfilter_add`: :bro:type:`function`            Adds an element to a Bloom filter.
:bro:id:`bloomfilter_basic_init`: :bro:type:`function`     Creates a basic Bloom filter.
:bro:id:`bloomfilter_basic_init2`: :bro:type:`function`    Creates a basic Bloom filter.
:bro:id:`bloomfilter_clear`: :bro:type:`function`          Removes all elements from a Bloom filter.
:bro:id:`bloomfilter_counting_init`: :bro:type:`function`  Creates a counting Bloom filter.
:bro:id:`bloomfilter_internal_state`: :bro:type:`function` Returns a string with a representation of a Bloom filter's internal
                                                           state.
:bro:id:`bloomfilter_lookup`: :bro:type:`function`         Retrieves the counter for a given element in a Bloom filter.
:bro:id:`bloomfilter_merge`: :bro:type:`function`          Merges two Bloom filters.
========================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: bloomfilter_add

   :Type: :bro:type:`function` (bf: :bro:type:`opaque` of bloomfilter, x: :bro:type:`any`) : :bro:type:`any`

   Adds an element to a Bloom filter.
   

   :bf: The Bloom filter handle.
   

   :x: The element to add.
   
   .. bro:see:: bloomfilter_basic_init bloomfilter_basic_init2 
      bloomfilter_counting_init bloomfilter_lookup bloomfilter_clear 
      bloomfilter_merge

.. bro:id:: bloomfilter_basic_init

   :Type: :bro:type:`function` (fp: :bro:type:`double`, capacity: :bro:type:`count`, name: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`opaque` of bloomfilter

   Creates a basic Bloom filter.
   

   :fp: The desired false-positive rate.
   

   :capacity: the maximum number of elements that guarantees a false-positive
             rate of *fp*.
   

   :name: A name that uniquely identifies and seeds the Bloom filter. If empty,
         the filter will use :bro:id:`global_hash_seed` if that's set, and
         otherwise use a local seed tied to the current Bro process. Only
         filters with the same seed can be merged with
         :bro:id:`bloomfilter_merge`.
   

   :returns: A Bloom filter handle.
   
   .. bro:see:: bloomfilter_basic_init2 bloomfilter_counting_init bloomfilter_add
      bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed

.. bro:id:: bloomfilter_basic_init2

   :Type: :bro:type:`function` (k: :bro:type:`count`, cells: :bro:type:`count`, name: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`opaque` of bloomfilter

   Creates a basic Bloom filter. This function serves as a low-level
   alternative to :bro:id:`bloomfilter_basic_init` where the user has full
   control over the number of hash functions and cells in the underlying bit
   vector.
   

   :k: The number of hash functions to use.
   

   :cells: The number of cells of the underlying bit vector.
   

   :name: A name that uniquely identifies and seeds the Bloom filter. If empty,
         the filter will use :bro:id:`global_hash_seed` if that's set, and
         otherwise use a local seed tied to the current Bro process. Only
         filters with the same seed can be merged with
         :bro:id:`bloomfilter_merge`.
   

   :returns: A Bloom filter handle.
   
   .. bro:see:: bloomfilter_basic_init bloomfilter_counting_init  bloomfilter_add
      bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed

.. bro:id:: bloomfilter_clear

   :Type: :bro:type:`function` (bf: :bro:type:`opaque` of bloomfilter) : :bro:type:`any`

   Removes all elements from a Bloom filter. This function resets all bits in
   the underlying bitvector back to 0 but does not change the parameterization
   of the Bloom filter, such as the element type and the hasher seed.
   

   :bf: The Bloom filter handle.
   
   .. bro:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_add bloomfilter_lookup
      bloomfilter_merge

.. bro:id:: bloomfilter_counting_init

   :Type: :bro:type:`function` (k: :bro:type:`count`, cells: :bro:type:`count`, max: :bro:type:`count`, name: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`opaque` of bloomfilter

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
         the filter will use :bro:id:`global_hash_seed` if that's set, and
         otherwise use a local seed tied to the current Bro process. Only
         filters with the same seed can be merged with
         :bro:id:`bloomfilter_merge`.
   

   :returns: A Bloom filter handle.
   
   .. bro:see:: bloomfilter_basic_init bloomfilter_basic_init2 bloomfilter_add
      bloomfilter_lookup bloomfilter_clear bloomfilter_merge global_hash_seed

.. bro:id:: bloomfilter_internal_state

   :Type: :bro:type:`function` (bf: :bro:type:`opaque` of bloomfilter) : :bro:type:`string`

   Returns a string with a representation of a Bloom filter's internal
   state. This is for debugging/testing purposes only.
   

   :bf: The Bloom filter handle.
   

   :returns: a string with a representation of a Bloom filter's internal state.

.. bro:id:: bloomfilter_lookup

   :Type: :bro:type:`function` (bf: :bro:type:`opaque` of bloomfilter, x: :bro:type:`any`) : :bro:type:`count`

   Retrieves the counter for a given element in a Bloom filter.
   

   :bf: The Bloom filter handle.
   

   :x: The element to count.
   

   :returns: the counter associated with *x* in *bf*.
   
   .. bro:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_add bloomfilter_clear
      bloomfilter_merge

.. bro:id:: bloomfilter_merge

   :Type: :bro:type:`function` (bf1: :bro:type:`opaque` of bloomfilter, bf2: :bro:type:`opaque` of bloomfilter) : :bro:type:`opaque` of bloomfilter

   Merges two Bloom filters.
   
   .. note:: Currently Bloom filters created by different Bro instances cannot
      be merged. In the future, this will be supported as long as both filters
      are created with the same name.
   

   :bf1: The first Bloom filter handle.
   

   :bf2: The second Bloom filter handle.
   

   :returns: The union of *bf1* and *bf2*.
   
   .. bro:see:: bloomfilter_basic_init bloomfilter_basic_init2
      bloomfilter_counting_init bloomfilter_add bloomfilter_lookup
      bloomfilter_clear


