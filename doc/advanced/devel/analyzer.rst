.. _devel-analyzer:

====================
Analyzer Development
====================


Analyzer Limits
===============

Starting with patch releases 8.0.11 and 9.0.1, Zeek has received a number of
configuration options to control the depth and limits of its protocol analysis
capabilities.

For example, the SSH analyzer now limits the size of strings within KEX init
packets, as well as caps the number of the variosu announced algorithms to a
configurable upper limit. See :zeek:see:`SSH::max_kexinit_kex_algorithms` or
:zeek:see:`SSH::max_string_length`.
Similarly, the MIME analyzer has had :zeek:see:`MIME::max_depth` for quite a
while. Recently, it was extended with :zeek:see:`MIME::max_header_bytes` and
:zeek:see:`MIME::max_header_continuation_lines` to cap the maximum size of
MIME header values parsed and exposed via Zeek scripting events.

When these limits are reached, the current pattern is that Zeek will report a
weird, naming the limit's script-level variable, suffixed with ``_reached``
or ``_exceeded``.
Additionally, the ``X`` code is added into the connection's
:zeek:field:`Conn::Info$history` field such that the occurrence of reaching
an analyzer limit is immediately available within ``conn.log``.

The currently (Zeek 9.1 timeframe) established patterns for limiting protocol
patterns is sketched below.


BinPAC and C++
--------------

* Add a :zeek:keyword:`const` and :zeek:attr:`&redef`-able global into the
  analyzer's module using a ``.bif`` file. This approach makes the constants
  directly accessible in BinPAC/C++ via, for example,
  ``zeek::BifConst::AnalyzerModule::max_kexinit_kex_algorithms``. Prefer
  analyzer specific ``consts.bif`` files, for example, ``http/consts.bif``
  over the global ``src/const.bif``.

* Within the analyzer's code, treat a value of ``0`` for a limit as unlimited,
  otherwise cap analysis according to the effective limit, raising a weird using
  the ``Analyzer::LimitReachedWeird(...)`` helper. Structure the weird as
  ``analyzer_limit_name_exceeded`` or ``analyzer_limit_name_reached``.
  Examples are ``DNS_max_compression_chain_depth_exceeded`` and
  ``imap_max_capabilities_reached``.

  Note that not all of the existing weird names are consistent, for example,
  the MIME analyzer uses ``exceeded_mime_max_depth`` or ``exceeded_mime_max_header_bytes``,
  instead of ``MIME_max_depth_exceeded``. Be consistent with existing limits in the
  same analyzer. Prefer the analyzer name first, cased like its module, and suffxing
  with ``_exceeded``.


.. note::

   There's ideas that reaching an analyzer limit should be a dedicated event
   rather than funneling the information through a weird as is done currently.

   See discussion `zeek/zeek#5785 <https://github.com/zeek/zeek/discussions/5785>`_.


Spicy
-----

Introduce script-level variables like outlined above, possibly only in
``init-bare.zeek`` as access ``zeek::BifConst::`` is not directly possible
like in BinPAC or C++.

Use Spicy's ``zeek::get_count()`` or similar to read the limit value
from the Zeek side. Cache it using an ``optional`` and ensure the lookup happens
only once. The ``zeek::get_count()`` helper goes through Zeek's global scope,
requiring a hashmap lookup and may result in significant overhead in hot paths.
A :zeek:keyword:`const` limit value does not change during runtime, so caching
is valid.

See ``redis/redis.spicy``'s ``Redis::max_value_size`` or
the ``SSL::max_certificates`` in ``ssl/spicy/SSL.spicy`` for examples.


Zeek Scripts
------------

When reporting limits from Zeek scripts instead of analyzer implementations,
use the :zeek:see:`Reporter::limit_reached_weird` function.

