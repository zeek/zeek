:tocdepth: 3

base/frameworks/input/readers/benchmark.zeek
============================================
.. bro:namespace:: InputBenchmark

Interface for the benchmark input reader.

:Namespace: InputBenchmark

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ =========================================================
:bro:id:`InputBenchmark::addfactor`: :bro:type:`count` :bro:attr:`&redef`    Addition factor for each heartbeat.
:bro:id:`InputBenchmark::autospread`: :bro:type:`double` :bro:attr:`&redef`  Spreading where usleep = 1000000 / autospread * num_lines
:bro:id:`InputBenchmark::factor`: :bro:type:`double` :bro:attr:`&redef`      Multiplication factor for each second.
:bro:id:`InputBenchmark::spread`: :bro:type:`count` :bro:attr:`&redef`       Spread factor between lines.
:bro:id:`InputBenchmark::stopspreadat`: :bro:type:`count` :bro:attr:`&redef` Stop spreading at x lines per heartbeat.
:bro:id:`InputBenchmark::timedspread`: :bro:type:`double` :bro:attr:`&redef` 1 -> enable timed spreading.
============================================================================ =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: InputBenchmark::addfactor

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   Addition factor for each heartbeat.

.. bro:id:: InputBenchmark::autospread

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0.0``

   Spreading where usleep = 1000000 / autospread * num_lines

.. bro:id:: InputBenchmark::factor

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0``

   Multiplication factor for each second.

.. bro:id:: InputBenchmark::spread

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   Spread factor between lines.

.. bro:id:: InputBenchmark::stopspreadat

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   Stop spreading at x lines per heartbeat.

.. bro:id:: InputBenchmark::timedspread

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0.0``

   1 -> enable timed spreading.


