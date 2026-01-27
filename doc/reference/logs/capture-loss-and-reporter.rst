=================================
capture_loss.log and reporter.log
=================================

Zeek produces several logs that tell administrators how well Zeek is managing
its analysis and reporting on network traffic.

This :file:`capture_loss.log` reports analysis of missing traffic. Zeek bases
its conclusions on analysis of TCP sequence numbers. When it detects a “gap,”
it assumes that the missing traffic corresponds to traffic loss.

The :file:`reporter.log` reports internal warnings and errors. Zeek generates
these based on how it is handling traffic and computing requirements.

Details on the format of each log appears in :zeek:see:`CaptureLoss::Info`
and :zeek:see:`Reporter::Info`.

:file:`capture_loss.log`
========================

The following is an example of entries in a :file:`capture_loss.log`:

.. literal-emph::

  {
    "ts": "2021-01-04T00:04:24.688236Z",
    "ts_delta": 900.0000550746918,
    "peer": "so16-enp0s8-1",
    "gaps": 41,
    "acks": 9944,
    **"percent_lost": 0.412308930008045**
  }
  {
    "ts": "2021-01-04T00:19:24.688265Z",
    "ts_delta": 900.0000290870667,
    "peer": "so16-enp0s8-1",
    "gaps": 9,
    "acks": 8530,
    **"percent_lost": 0.10550996483001172**
  }
  {
    "ts": "2021-01-04T00:34:24.688449Z",
    "ts_delta": 900.0001838207245,
    "peer": "so16-enp0s8-1",
    "gaps": 0,
    "acks": 52019,
    **"percent_lost": 0**
  }
  {
    "ts": "2021-01-04T00:49:24.688552Z",
    "ts_delta": 900.0001029968262,
    "peer": "so16-enp0s8-1",
    "gaps": 0,
    "acks": 108863,
    **"percent_lost": 0**
  }

In these logs, capture loss never exceeded 1%. For example, when Zeek reports
``0.412308930008045``, that means 0.4123% capture loss, not 41.23% capture
loss.  In other words, this sensor is doing well capturing the traffic on the
link it monitors (a small amount of loss is tolerable).

:file:`reporter.log`
====================

The following is an example entries in the :file:`reporter.log`:

.. literal-emph::

  {
    "ts": "2021-01-04T01:15:02.622164Z",
    "level": "Reporter::INFO",
    **"message": "received termination signal",**
    "location": ""
  }
  {
    "ts": "2021-01-04T01:19:15.713689Z",
    "level": "Reporter::INFO",
    **"message": "BPFConf filename set: /etc/nsm/so16-enp0s8/bpf-bro.conf (logger)",**
    "location": "/opt/bro/share/zeek/securityonion/./bpfconf.zeek, line 81"
  }
  {
    "ts": "2021-01-04T01:19:22.786812Z",
    "level": "Reporter::INFO",
    **"message": "BPFConf filename set: /etc/nsm/so16-enp0s8/bpf-bro.conf (proxy)",**
    "location": "/opt/bro/share/zeek/securityonion/./bpfconf.zeek, line 81"
  }

The first message refers to Zeek receiving a termination signal. The second two
messages refer to Zeek setting a file for configuring Berkeley Packet Filters.

Conclusion
==========

The :file:`capture_loss.log` and :file:`reporter.log` files are helpful when
administrators need to understand how their Zeek deployment is performing. Keep
an eye on the :file:`capture_loss.log` to keep the performance within an
acceptable level.
