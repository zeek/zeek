:tocdepth: 3

base/bif/telemetry_functions.bif.zeek
=====================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Telemetry

Functions for accessing counter metrics from script land.

:Namespaces: GLOBAL, Telemetry

Summary
~~~~~~~
Functions
#########
========================================================================== =
:zeek:id:`Telemetry::__collect_histogram_metrics`: :zeek:type:`function`
:zeek:id:`Telemetry::__collect_metrics`: :zeek:type:`function`
:zeek:id:`Telemetry::__counter_family`: :zeek:type:`function`
:zeek:id:`Telemetry::__counter_inc`: :zeek:type:`function`
:zeek:id:`Telemetry::__counter_metric_get_or_add`: :zeek:type:`function`
:zeek:id:`Telemetry::__counter_value`: :zeek:type:`function`
:zeek:id:`Telemetry::__gauge_dec`: :zeek:type:`function`
:zeek:id:`Telemetry::__gauge_family`: :zeek:type:`function`
:zeek:id:`Telemetry::__gauge_inc`: :zeek:type:`function`
:zeek:id:`Telemetry::__gauge_metric_get_or_add`: :zeek:type:`function`
:zeek:id:`Telemetry::__gauge_value`: :zeek:type:`function`
:zeek:id:`Telemetry::__histogram_family`: :zeek:type:`function`
:zeek:id:`Telemetry::__histogram_metric_get_or_add`: :zeek:type:`function`
:zeek:id:`Telemetry::__histogram_observe`: :zeek:type:`function`
:zeek:id:`Telemetry::__histogram_sum`: :zeek:type:`function`
========================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Telemetry::__collect_histogram_metrics
   :source-code: base/bif/telemetry_functions.bif.zeek 61 61

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`) : :zeek:type:`any_vec`


.. zeek:id:: Telemetry::__collect_metrics
   :source-code: base/bif/telemetry_functions.bif.zeek 58 58

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`) : :zeek:type:`any_vec`


.. zeek:id:: Telemetry::__counter_family
   :source-code: base/bif/telemetry_functions.bif.zeek 15 15

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, labels: :zeek:type:`string_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of counter_metric_family


.. zeek:id:: Telemetry::__counter_inc
   :source-code: base/bif/telemetry_functions.bif.zeek 21 21

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of counter_metric, amount: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__counter_metric_get_or_add
   :source-code: base/bif/telemetry_functions.bif.zeek 18 18

   :Type: :zeek:type:`function` (family: :zeek:type:`opaque` of counter_metric_family, labels: :zeek:type:`table_string_of_string`) : :zeek:type:`opaque` of counter_metric


.. zeek:id:: Telemetry::__counter_value
   :source-code: base/bif/telemetry_functions.bif.zeek 24 24

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of counter_metric) : :zeek:type:`double`


.. zeek:id:: Telemetry::__gauge_dec
   :source-code: base/bif/telemetry_functions.bif.zeek 38 38

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of gauge_metric, amount: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__gauge_family
   :source-code: base/bif/telemetry_functions.bif.zeek 29 29

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, labels: :zeek:type:`string_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of gauge_metric_family


.. zeek:id:: Telemetry::__gauge_inc
   :source-code: base/bif/telemetry_functions.bif.zeek 35 35

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of gauge_metric, amount: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__gauge_metric_get_or_add
   :source-code: base/bif/telemetry_functions.bif.zeek 32 32

   :Type: :zeek:type:`function` (family: :zeek:type:`opaque` of gauge_metric_family, labels: :zeek:type:`table_string_of_string`) : :zeek:type:`opaque` of gauge_metric


.. zeek:id:: Telemetry::__gauge_value
   :source-code: base/bif/telemetry_functions.bif.zeek 41 41

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of gauge_metric) : :zeek:type:`double`


.. zeek:id:: Telemetry::__histogram_family
   :source-code: base/bif/telemetry_functions.bif.zeek 46 46

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, labels: :zeek:type:`string_vec`, bounds: :zeek:type:`double_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of histogram_metric_family


.. zeek:id:: Telemetry::__histogram_metric_get_or_add
   :source-code: base/bif/telemetry_functions.bif.zeek 49 49

   :Type: :zeek:type:`function` (family: :zeek:type:`opaque` of histogram_metric_family, labels: :zeek:type:`table_string_of_string`) : :zeek:type:`opaque` of histogram_metric


.. zeek:id:: Telemetry::__histogram_observe
   :source-code: base/bif/telemetry_functions.bif.zeek 52 52

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of histogram_metric, measurement: :zeek:type:`double`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__histogram_sum
   :source-code: base/bif/telemetry_functions.bif.zeek 55 55

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of histogram_metric) : :zeek:type:`double`



