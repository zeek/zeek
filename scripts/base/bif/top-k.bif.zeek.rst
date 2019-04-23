:tocdepth: 3

base/bif/top-k.bif.zeek
=======================
.. zeek:namespace:: GLOBAL

Functions to probabilistically determine top-k elements.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
================================================== ==========================================================================
:zeek:id:`topk_add`: :zeek:type:`function`         Add a new observed object to the data structure.
:zeek:id:`topk_count`: :zeek:type:`function`       Get an overestimated count of how often a value has been encountered.
:zeek:id:`topk_epsilon`: :zeek:type:`function`     Get the maximal overestimation for count.
:zeek:id:`topk_get_top`: :zeek:type:`function`     Get the first *k* elements of the top-k data structure.
:zeek:id:`topk_init`: :zeek:type:`function`        Creates a top-k data structure which tracks *size* elements.
:zeek:id:`topk_merge`: :zeek:type:`function`       Merge the second top-k data structure into the first.
:zeek:id:`topk_merge_prune`: :zeek:type:`function` Merge the second top-k data structure into the first and prunes the final
                                                   data structure back to the size given on initialization.
:zeek:id:`topk_size`: :zeek:type:`function`        Get the number of elements this data structure is supposed to track (given
                                                   on init).
:zeek:id:`topk_sum`: :zeek:type:`function`         Get the sum of all counts of all elements in the data structure.
================================================== ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: topk_add

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of topk, value: :zeek:type:`any`) : :zeek:type:`any`

   Add a new observed object to the data structure.
   
   .. note:: The first added object sets the type of data tracked by
      the top-k data structure. All following values have to be of the same
      type.
   

   :handle: the TopK handle.
   

   :value: observed value.
   
   .. zeek:see:: topk_init topk_get_top topk_count topk_epsilon
      topk_size topk_sum topk_merge topk_merge_prune

.. zeek:id:: topk_count

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of topk, value: :zeek:type:`any`) : :zeek:type:`count`

   Get an overestimated count of how often a value has been encountered.
   
   .. note:: The value has to be part of the currently tracked elements,
      otherwise 0 will be returned and an error message will be added to
      reporter.
   

   :handle: the TopK handle.
   

   :value: Value to look up count for.
   

   :returns: Overestimated number for how often the element has been encountered.
   
   .. zeek:see:: topk_init topk_add topk_get_top topk_epsilon
      topk_size topk_sum topk_merge topk_merge_prune

.. zeek:id:: topk_epsilon

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of topk, value: :zeek:type:`any`) : :zeek:type:`count`

   Get the maximal overestimation for count.
   
   .. note:: Same restrictions as for :zeek:id:`topk_count` apply.
   

   :handle: the TopK handle.
   

   :value: Value to look up epsilon for.
   

   :returns: Number which represents the maximal overestimation for the count of
            this element.
   
   .. zeek:see:: topk_init topk_add topk_get_top topk_count
      topk_size topk_sum topk_merge topk_merge_prune

.. zeek:id:: topk_get_top

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of topk, k: :zeek:type:`count`) : :zeek:type:`any_vec`

   Get the first *k* elements of the top-k data structure.
   

   :handle: the TopK handle.
   

   :k: number of elements to return.
   

   :returns: vector of the first k elements.
   
   .. zeek:see:: topk_init topk_add topk_count topk_epsilon
      topk_size topk_sum topk_merge topk_merge_prune

.. zeek:id:: topk_init

   :Type: :zeek:type:`function` (size: :zeek:type:`count`) : :zeek:type:`opaque` of topk

   Creates a top-k data structure which tracks *size* elements.
   

   :size: number of elements to track.
   

   :returns: Opaque pointer to the data structure.
   
   .. zeek:see:: topk_add topk_get_top topk_count topk_epsilon
      topk_size topk_sum topk_merge topk_merge_prune

.. zeek:id:: topk_merge

   :Type: :zeek:type:`function` (handle1: :zeek:type:`opaque` of topk, handle2: :zeek:type:`opaque` of topk) : :zeek:type:`any`

   Merge the second top-k data structure into the first.
   

   :handle1: the first TopK handle.
   

   :handle2: the second TopK handle.
   
   .. note:: This does not remove any elements, the resulting data structure
      can be bigger than the maximum size given on initialization.
   
   .. zeek:see:: topk_init topk_add topk_get_top topk_count topk_epsilon
      topk_size topk_sum topk_merge_prune

.. zeek:id:: topk_merge_prune

   :Type: :zeek:type:`function` (handle1: :zeek:type:`opaque` of topk, handle2: :zeek:type:`opaque` of topk) : :zeek:type:`any`

   Merge the second top-k data structure into the first and prunes the final
   data structure back to the size given on initialization.
   
   .. note:: Use with care and only when being aware of the restrictions this
      entails. Do not call :zeek:id:`topk_size` or :zeek:id:`topk_add` afterwards,
      results will probably not be what you expect.
   

   :handle1: the TopK handle in which the second TopK structure is merged.
   

   :handle2: the TopK handle in which is merged into the first TopK structure.
   
   .. zeek:see:: topk_init topk_add topk_get_top topk_count topk_epsilon
      topk_size topk_sum topk_merge

.. zeek:id:: topk_size

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of topk) : :zeek:type:`count`

   Get the number of elements this data structure is supposed to track (given
   on init).
   
   .. note:: Note that the actual number of elements in the data structure can
      be lower or higher (due to non-pruned merges) than this.
   

   :handle: the TopK handle.
   

   :returns: size given during initialization.
   
   .. zeek:see:: topk_init topk_add topk_get_top topk_count topk_epsilon
      topk_sum topk_merge topk_merge_prune

.. zeek:id:: topk_sum

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of topk) : :zeek:type:`count`

   Get the sum of all counts of all elements in the data structure.
   
   .. note:: This is equal to the number of all inserted objects if the data
      structure never has been pruned. Do not use after
      calling :zeek:id:`topk_merge_prune` (will throw a warning message if used
      afterwards).
   

   :handle: the TopK handle.
   

   :returns: sum of all counts.
   
   .. zeek:see:: topk_init topk_add topk_get_top topk_count topk_epsilon
      topk_size topk_merge topk_merge_prune


