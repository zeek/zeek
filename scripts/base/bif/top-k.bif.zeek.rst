:tocdepth: 3

base/bif/top-k.bif.zeek
=======================
.. bro:namespace:: GLOBAL

Functions to probabilistically determine top-k elements.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
================================================ ==========================================================================
:bro:id:`topk_add`: :bro:type:`function`         Add a new observed object to the data structure.
:bro:id:`topk_count`: :bro:type:`function`       Get an overestimated count of how often a value has been encountered.
:bro:id:`topk_epsilon`: :bro:type:`function`     Get the maximal overestimation for count.
:bro:id:`topk_get_top`: :bro:type:`function`     Get the first *k* elements of the top-k data structure.
:bro:id:`topk_init`: :bro:type:`function`        Creates a top-k data structure which tracks *size* elements.
:bro:id:`topk_merge`: :bro:type:`function`       Merge the second top-k data structure into the first.
:bro:id:`topk_merge_prune`: :bro:type:`function` Merge the second top-k data structure into the first and prunes the final
                                                 data structure back to the size given on initialization.
:bro:id:`topk_size`: :bro:type:`function`        Get the number of elements this data structure is supposed to track (given
                                                 on init).
:bro:id:`topk_sum`: :bro:type:`function`         Get the sum of all counts of all elements in the data structure.
================================================ ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: topk_add

   :Type: :bro:type:`function` (handle: :bro:type:`opaque` of topk, value: :bro:type:`any`) : :bro:type:`any`

   Add a new observed object to the data structure.
   
   .. note:: The first added object sets the type of data tracked by
      the top-k data structure. All following values have to be of the same
      type.
   

   :handle: the TopK handle.
   

   :value: observed value.
   
   .. bro:see:: topk_init topk_get_top topk_count topk_epsilon
      topk_size topk_sum topk_merge topk_merge_prune

.. bro:id:: topk_count

   :Type: :bro:type:`function` (handle: :bro:type:`opaque` of topk, value: :bro:type:`any`) : :bro:type:`count`

   Get an overestimated count of how often a value has been encountered.
   
   .. note:: The value has to be part of the currently tracked elements,
      otherwise 0 will be returned and an error message will be added to
      reporter.
   

   :handle: the TopK handle.
   

   :value: Value to look up count for.
   

   :returns: Overestimated number for how often the element has been encountered.
   
   .. bro:see:: topk_init topk_add topk_get_top topk_epsilon
      topk_size topk_sum topk_merge topk_merge_prune

.. bro:id:: topk_epsilon

   :Type: :bro:type:`function` (handle: :bro:type:`opaque` of topk, value: :bro:type:`any`) : :bro:type:`count`

   Get the maximal overestimation for count.
   
   .. note:: Same restrictions as for :bro:id:`topk_count` apply.
   

   :handle: the TopK handle.
   

   :value: Value to look up epsilon for.
   

   :returns: Number which represents the maximal overestimation for the count of
            this element.
   
   .. bro:see:: topk_init topk_add topk_get_top topk_count
      topk_size topk_sum topk_merge topk_merge_prune

.. bro:id:: topk_get_top

   :Type: :bro:type:`function` (handle: :bro:type:`opaque` of topk, k: :bro:type:`count`) : :bro:type:`any_vec`

   Get the first *k* elements of the top-k data structure.
   

   :handle: the TopK handle.
   

   :k: number of elements to return.
   

   :returns: vector of the first k elements.
   
   .. bro:see:: topk_init topk_add topk_count topk_epsilon
      topk_size topk_sum topk_merge topk_merge_prune

.. bro:id:: topk_init

   :Type: :bro:type:`function` (size: :bro:type:`count`) : :bro:type:`opaque` of topk

   Creates a top-k data structure which tracks *size* elements.
   

   :size: number of elements to track.
   

   :returns: Opaque pointer to the data structure.
   
   .. bro:see:: topk_add topk_get_top topk_count topk_epsilon
      topk_size topk_sum topk_merge topk_merge_prune

.. bro:id:: topk_merge

   :Type: :bro:type:`function` (handle1: :bro:type:`opaque` of topk, handle2: :bro:type:`opaque` of topk) : :bro:type:`any`

   Merge the second top-k data structure into the first.
   

   :handle1: the first TopK handle.
   

   :handle2: the second TopK handle.
   
   .. note:: This does not remove any elements, the resulting data structure
      can be bigger than the maximum size given on initialization.
   
   .. bro:see:: topk_init topk_add topk_get_top topk_count topk_epsilon
      topk_size topk_sum topk_merge_prune

.. bro:id:: topk_merge_prune

   :Type: :bro:type:`function` (handle1: :bro:type:`opaque` of topk, handle2: :bro:type:`opaque` of topk) : :bro:type:`any`

   Merge the second top-k data structure into the first and prunes the final
   data structure back to the size given on initialization.
   
   .. note:: Use with care and only when being aware of the restrictions this
      entails. Do not call :bro:id:`topk_size` or :bro:id:`topk_add` afterwards,
      results will probably not be what you expect.
   

   :handle1: the TopK handle in which the second TopK structure is merged.
   

   :handle2: the TopK handle in which is merged into the first TopK structure.
   
   .. bro:see:: topk_init topk_add topk_get_top topk_count topk_epsilon
      topk_size topk_sum topk_merge

.. bro:id:: topk_size

   :Type: :bro:type:`function` (handle: :bro:type:`opaque` of topk) : :bro:type:`count`

   Get the number of elements this data structure is supposed to track (given
   on init).
   
   .. note:: Note that the actual number of elements in the data structure can
      be lower or higher (due to non-pruned merges) than this.
   

   :handle: the TopK handle.
   

   :returns: size given during initialization.
   
   .. bro:see:: topk_init topk_add topk_get_top topk_count topk_epsilon
      topk_sum topk_merge topk_merge_prune

.. bro:id:: topk_sum

   :Type: :bro:type:`function` (handle: :bro:type:`opaque` of topk) : :bro:type:`count`

   Get the sum of all counts of all elements in the data structure.
   
   .. note:: This is equal to the number of all inserted objects if the data
      structure never has been pruned. Do not use after
      calling :bro:id:`topk_merge_prune` (will throw a warning message if used
      afterwards).
   

   :handle: the TopK handle.
   

   :returns: sum of all counts.
   
   .. bro:see:: topk_init topk_add topk_get_top topk_count topk_epsilon
      topk_size topk_merge topk_merge_prune


