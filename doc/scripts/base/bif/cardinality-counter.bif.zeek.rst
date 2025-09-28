:tocdepth: 3

base/bif/cardinality-counter.bif.zeek
=====================================
.. zeek:namespace:: GLOBAL

Functions to create and manipulate probabilistic cardinality counters.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
============================================================ =========================================================================
:zeek:id:`hll_cardinality_add`: :zeek:type:`function`        Adds an element to a HyperLogLog cardinality counter.
:zeek:id:`hll_cardinality_copy`: :zeek:type:`function`       Copy a HLL cardinality counter.
:zeek:id:`hll_cardinality_estimate`: :zeek:type:`function`   Estimate the current cardinality of an HLL cardinality counter.
:zeek:id:`hll_cardinality_init`: :zeek:type:`function`       Initializes a probabilistic cardinality counter that uses the HyperLogLog
                                                             algorithm.
:zeek:id:`hll_cardinality_merge_into`: :zeek:type:`function` Merges a HLL cardinality counter into another.
============================================================ =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: hll_cardinality_add
   :source-code: base/bif/cardinality-counter.bif.zeek 35 35

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of cardinality, elem: :zeek:type:`any`) : :zeek:type:`bool`

   Adds an element to a HyperLogLog cardinality counter.
   

   :param handle: the HLL handle.
   

   :param elem: the element to add.
   

   :returns: true on success.
   
   .. zeek:see:: hll_cardinality_estimate hll_cardinality_merge_into
      hll_cardinality_init hll_cardinality_copy

.. zeek:id:: hll_cardinality_copy
   :source-code: base/bif/cardinality-counter.bif.zeek 73 73

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of cardinality) : :zeek:type:`opaque` of cardinality

   Copy a HLL cardinality counter.
   

   :param handle: cardinality counter to copy.
   

   :returns: copy of handle.
   
   .. zeek:see:: hll_cardinality_estimate hll_cardinality_merge_into hll_cardinality_add
      hll_cardinality_init

.. zeek:id:: hll_cardinality_estimate
   :source-code: base/bif/cardinality-counter.bif.zeek 62 62

   :Type: :zeek:type:`function` (handle: :zeek:type:`opaque` of cardinality) : :zeek:type:`double`

   Estimate the current cardinality of an HLL cardinality counter.
   

   :param handle: the HLL handle.
   

   :returns: the cardinality estimate. Returns -1.0 if the counter is empty.
   
   .. zeek:see:: hll_cardinality_merge_into hll_cardinality_add
      hll_cardinality_init hll_cardinality_copy

.. zeek:id:: hll_cardinality_init
   :source-code: base/bif/cardinality-counter.bif.zeek 22 22

   :Type: :zeek:type:`function` (err: :zeek:type:`double`, confidence: :zeek:type:`double`) : :zeek:type:`opaque` of cardinality

   Initializes a probabilistic cardinality counter that uses the HyperLogLog
   algorithm.
   

   :param err: the desired error rate (e.g. 0.01).
   

   :param confidence: the desired confidence for the error rate (e.g., 0.95).
   

   :returns: a HLL cardinality handle.
   
   .. zeek:see:: hll_cardinality_estimate hll_cardinality_merge_into hll_cardinality_add
      hll_cardinality_copy

.. zeek:id:: hll_cardinality_merge_into
   :source-code: base/bif/cardinality-counter.bif.zeek 51 51

   :Type: :zeek:type:`function` (handle1: :zeek:type:`opaque` of cardinality, handle2: :zeek:type:`opaque` of cardinality) : :zeek:type:`bool`

   Merges a HLL cardinality counter into another.
   
   .. note:: The same restrictions as for Bloom filter merging apply,
      see :zeek:id:`bloomfilter_merge`.
   

   :param handle1: the first HLL handle, which will contain the merged result.
   

   :param handle2: the second HLL handle, which will be merged into the first.
   

   :returns: true on success.
   
   .. zeek:see:: hll_cardinality_estimate  hll_cardinality_add
      hll_cardinality_init hll_cardinality_copy


