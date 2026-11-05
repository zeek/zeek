.. _devel-analyzer:

====================
Analyzer Development
====================


Analyzer Limits
===============

Starting with patch releases 8.0.11 and 9.0.1, Zeek has received a number of
configuration options to control the depth and limits of its protocol analysis
capabilities. This has primarily been driven by LLM-based security scanners
being very good at finding abusive behavior in protocols that normal traffic
does not trigger, yet can be exploited to mount denial-of-service attacks
on Zeek itself.

For example, the SSH analyzer now limits the size of strings within SSH Key Exchange Init
packets, and caps the number of the various announced algorithms to a
configurable upper limit. See :zeek:see:`SSH::max_kexinit_kex_algorithms` or
:zeek:see:`SSH::max_string_length`.
Similarly, the MIME analyzer has had :zeek:see:`MIME::max_depth` for quite a
while. Recently, the MIME analyzer was extended with :zeek:see:`MIME::max_header_bytes` and
:zeek:see:`MIME::max_header_continuation_lines` to cap the maximum size of
MIME header values parsed and exposed via Zeek scripting events.

When these limits are reached, the current pattern is that Zeek will report a
weird, naming the limit's script-level variable, suffixed with ``_reached``
or ``_exceeded``.
Additionally, the ``X`` code should be added into the connection's
:zeek:field:`Conn::Info$history` field such that the occurrence of reaching
an analyzer limit is immediately available as a signal within ``conn.log``.

The current (Zeek 9.1 timeframe) pattern for adding analyzer limits is sketched below.


BinPAC and C++
--------------

* Add a :zeek:keyword:`const` and :zeek:attr:`&redef`-able global into the
  analyzer's module using a ``.bif`` file. This approach makes the constants
  directly accessible in BinPAC/C++ via, for example,
  ``zeek::BifConst::SSH::max_kexinit_kex_algorithms``.
  Prefer analyzer specific ``consts.bif`` files, like ``http/consts.bif``, over
  the global ``src/const.bif``. The default value and its Zeekygen documentation
  is added to the ``scripts/init-bare.zeek`` file.

* Within the analyzer's code, treat a value of ``0`` as unlimited, otherwise cap
  analysis according to the effective limit, raising a weird using
  the ``Analyzer::LimitReachedWeird(...)`` helper. Structure the weird as
  ``analyzer_limit_name_exceeded`` or ``analyzer_limit_name_reached``.
  Existing examples are ``DNS_max_compression_chain_depth_exceeded`` or
  ``imap_max_capabilities_reached``.

  Note that not all of the existing weird names are consistent, for example,
  the MIME analyzer uses ``exceeded_mime_max_depth`` or ``exceeded_mime_max_header_bytes``,
  instead of ``MIME_max_depth_exceeded``. Be consistent with existing limits in the
  same analyzer. Prefer the analyzer name first, cased like its script-level module,
  and suffixing the weird name with ``_exceeded``.


.. note::

   We are considering reporting analyzer limits from a dedicated event
   rather than funneling the information through a weird.

   See discussion `zeek/zeek#5785 <https://github.com/zeek/zeek/discussions/5785>`_.

   It is possible to use the :zeek:see:`conn_weird` event to intercept the generated
   weird within Zeek script and act on it.


Spicy
-----

Introduce script-level variables like outlined above, possibly only in
``scirpts/init-bare.zeek`` as access to ``zeek::BifConst::`` is not directly
possible from Spicy code like it is with BinPAC or C++.

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


Testing
-------

Testing of analyzer limits is done using btest regression tests. See the
:ref:`devel-btest` section to learn about testing.

Generally, the default values for limits are set such that they should never trigger
for normal traffic. For testing, the preferred approach is to lower the limits
via :zeek:keyword:`redef` and observe ``weird.log`` entries as well as the ``X``
in the connection's history.

The following btest file is an example for testing the SSH analyzer limits
mentioned above. The traffic is synthetic and produced via ``kex-quadratic-1000.pcap.py``.
As it contains thousands of similarly named algorithms, it compresses really well
and the PCAP file is stored as ``.gz`` and decompressed via ``zcat`` in the test.

.. code-block:: shell

    # @TEST-DOC: Verify the max_kexinit limits work.

    # @TEST-EXEC: zcat < $TRACES/ssh/kex-quadratic-1000.pcap.gz | zeek -b -r - %INPUT
    # @TEST-EXEC: btest-diff-cut -m uid id.orig_h id.resp_h name addl notice source weird.log
    # @TEST-EXEC: btest-diff-cut -m uid service history conn.log

    @load base/protocols/conn
    @load base/protocols/ssh
    @load base/frameworks/notice/weird

    redef SSH::max_kexinit_kex_algorithms = 101;
    redef SSH::max_kexinit_hostkey_algorithms = 102;
    redef SSH::max_kexinit_encryption_algorithms = 103;
    redef SSH::max_kexinit_mac_algorithms = 104;
    redef SSH::max_kexinit_compression_algorithms = 105;
    redef SSH::max_kexinit_languages = 106;

The ``weird.log`` and ``conn.log`` baselines look as follows:

.. code-block:: shell

    uid     id.orig_h       id.resp_h       name    addl    notice  source
    CHhAvVGS1DHFjwGM9       10.0.1.1        10.0.1.2        SSH_max_kexinit_kex_algorithms_exceeded 500 > 101       F       SSH
    CHhAvVGS1DHFjwGM9       10.0.1.1        10.0.1.2        SSH_max_kexinit_hostkey_algorithms_exceeded     510 > 102       F       SSH
    CHhAvVGS1DHFjwGM9       10.0.1.1        10.0.1.2        SSH_max_kexinit_encryption_algorithms_exceeded  520 > 103       F       SSH
    CHhAvVGS1DHFjwGM9       10.0.1.1        10.0.1.2        SSH_max_kexinit_mac_algorithms_exceeded 540 > 104       F       SSH
    CHhAvVGS1DHFjwGM9       10.0.1.1        10.0.1.2        SSH_max_kexinit_compression_algorithms_exceeded 560 > 105       F       SSH
    CHhAvVGS1DHFjwGM9       10.0.1.1        10.0.1.2        SSH_max_kexinit_languages_exceeded      580 > 106       F       SSH

.. code-block:: shell

   uid     service history
   CHhAvVGS1DHFjwGM9       -       ShADadX
