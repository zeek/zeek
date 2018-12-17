:tocdepth: 3

base/bif/cardinality-counter.bif.bro
====================================
.. bro:namespace:: GLOBAL

Functions to create and manipulate probabilistic cardinality counters.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================== =========================================================================
:bro:id:`hll_cardinality_add`: :bro:type:`function`        Adds an element to a HyperLogLog cardinality counter.
:bro:id:`hll_cardinality_copy`: :bro:type:`function`       Copy a HLL cardinality counter.
:bro:id:`hll_cardinality_estimate`: :bro:type:`function`   Estimate the current cardinality of an HLL cardinality counter.
:bro:id:`hll_cardinality_init`: :bro:type:`function`       Initializes a probabilistic cardinality counter that uses the HyperLogLog
                                                           algorithm.
:bro:id:`hll_cardinality_merge_into`: :bro:type:`function` Merges a HLL cardinality counter into another.
========================================================== =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: hll_cardinality_add

   :Type: :bro:type:`function` (handle: :bro:type:`opaque` of cardinality, elem: :bro:type:`any`) : :bro:type:`bool`

   Adds an element to a HyperLogLog cardinality counter.
   

   :handle: the HLL handle.
   

   :elem: the element to add.
   

   :returns: true on success.
   
   .. bro:see:: hll_cardinality_estimate hll_cardinality_merge_into
      hll_cardinality_init hll_cardinality_copy

.. bro:id:: hll_cardinality_copy

   :Type: :bro:type:`function` (handle: :bro:type:`opaque` of cardinality) : :bro:type:`opaque` of cardinality

   Copy a HLL cardinality counter.
   

   :handle: cardinality counter to copy.
   

   :returns: copy of handle.
   
   .. bro:see:: hll_cardinality_estimate hll_cardinality_merge_into hll_cardinality_add
      hll_cardinality_init

.. bro:id:: hll_cardinality_estimate

   :Type: :bro:type:`function` (handle: :bro:type:`opaque` of cardinality) : :bro:type:`double`

   Estimate the current cardinality of an HLL cardinality counter.
   

   :handle: the HLL handle.
   

   :returns: the cardinality estimate. Returns -1.0 if the counter is empty.
   
   .. bro:see:: hll_cardinality_merge_into hll_cardinality_add
      hll_cardinality_init hll_cardinality_copy

.. bro:id:: hll_cardinality_init

   :Type: :bro:type:`function` (err: :bro:type:`double`, confidence: :bro:type:`double`) : :bro:type:`opaque` of cardinality

   Initializes a probabilistic cardinality counter that uses the HyperLogLog
   algorithm.
   

   :err: the desired error rate (e.g. 0.01).
   

   :confidence: the desired confidence for the error rate (e.g., 0.95).
   

   :returns: a HLL cardinality handle.
   
   .. bro:see:: hll_cardinality_estimate hll_cardinality_merge_into hll_cardinality_add
      hll_cardinality_copy

.. bro:id:: hll_cardinality_merge_into

   :Type: :bro:type:`function` (handle1: :bro:type:`opaque` of cardinality, handle2: :bro:type:`opaque` of cardinality) : :bro:type:`bool`

   Merges a HLL cardinality counter into another.
   
   .. note:: The same restrictions as for Bloom filter merging apply,
      see :bro:id:`bloomfilter_merge`.
   

   :handle1: the first HLL handle, which will contain the merged result.
   

   :handle2: the second HLL handle, which will be merged into the first.
   

   :returns: true on success.
   
   .. bro:see:: hll_cardinality_estimate  hll_cardinality_add
      hll_cardinality_init hll_cardinality_copy


