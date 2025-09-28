:tocdepth: 3

base/frameworks/input/readers/benchmark.zeek
============================================
.. zeek:namespace:: InputBenchmark

Interface for the benchmark input reader.

:Namespace: InputBenchmark

Summary
~~~~~~~
Redefinable Options
###################
=============================================================================== =========================================================
:zeek:id:`InputBenchmark::addfactor`: :zeek:type:`count` :zeek:attr:`&redef`    Addition factor for each heartbeat.
:zeek:id:`InputBenchmark::autospread`: :zeek:type:`double` :zeek:attr:`&redef`  Spreading where usleep = 1000000 / autospread * num_lines
:zeek:id:`InputBenchmark::factor`: :zeek:type:`double` :zeek:attr:`&redef`      Multiplication factor for each second.
:zeek:id:`InputBenchmark::spread`: :zeek:type:`count` :zeek:attr:`&redef`       Spread factor between lines.
:zeek:id:`InputBenchmark::stopspreadat`: :zeek:type:`count` :zeek:attr:`&redef` Stop spreading at x lines per heartbeat.
:zeek:id:`InputBenchmark::timedspread`: :zeek:type:`double` :zeek:attr:`&redef` 1 -> enable timed spreading.
=============================================================================== =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: InputBenchmark::addfactor
   :source-code: base/frameworks/input/readers/benchmark.zeek 16 16

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   Addition factor for each heartbeat.

.. zeek:id:: InputBenchmark::autospread
   :source-code: base/frameworks/input/readers/benchmark.zeek 13 13

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0.0``

   Spreading where usleep = 1000000 / autospread * num_lines

.. zeek:id:: InputBenchmark::factor
   :source-code: base/frameworks/input/readers/benchmark.zeek 7 7

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0``

   Multiplication factor for each second.

.. zeek:id:: InputBenchmark::spread
   :source-code: base/frameworks/input/readers/benchmark.zeek 10 10

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   Spread factor between lines.

.. zeek:id:: InputBenchmark::stopspreadat
   :source-code: base/frameworks/input/readers/benchmark.zeek 19 19

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   Stop spreading at x lines per heartbeat.

.. zeek:id:: InputBenchmark::timedspread
   :source-code: base/frameworks/input/readers/benchmark.zeek 22 22

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0.0``

   1 -> enable timed spreading.


