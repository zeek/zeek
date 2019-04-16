:tocdepth: 3

base/protocols/ftp/gridftp.zeek
===============================
.. bro:namespace:: GridFTP

A detection script for GridFTP data and control channels.

GridFTP control channels are identified by FTP control channels
that successfully negotiate the GSSAPI method of an AUTH request
and for which the exchange involved an encoded TLS/SSL handshake,
indicating the GSI mechanism for GSSAPI was used.  This analysis
is all supported internally, this script simply adds the "gridftp"
label to the *service* field of the control channel's
:bro:type:`connection` record.

GridFTP data channels are identified by a heuristic that relies on
the fact that default settings for GridFTP clients typically
mutually authenticate the data channel with TLS/SSL and negotiate a
NULL bulk cipher (no encryption). Connections with those attributes
are marked as GridFTP if the data transfer within the first two minutes
is big enough to indicate a GripFTP data channel that would be
undesirable to analyze further (e.g. stop TCP reassembly).  A side
effect is that true connection sizes are not logged, but at the benefit
of saving CPU cycles that would otherwise go to analyzing the large
(and likely benign) connections.

:Namespace: GridFTP
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`, :doc:`base/protocols/ftp/info.zeek </scripts/base/protocols/ftp/info.zeek>`, :doc:`base/protocols/ftp/main.zeek </scripts/base/protocols/ftp/main.zeek>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================= ===================================================================
:bro:id:`GridFTP::max_time`: :bro:type:`interval` :bro:attr:`&redef`    Time during which we check whether a connection's size exceeds the
                                                                        :bro:see:`GridFTP::size_threshold`.
:bro:id:`GridFTP::size_threshold`: :bro:type:`count` :bro:attr:`&redef` Number of bytes transferred before guessing a connection is a
                                                                        GridFTP data channel.
:bro:id:`GridFTP::skip_data`: :bro:type:`bool` :bro:attr:`&redef`       Whether to skip further processing of the GridFTP data channel once
                                                                        detected, which may help performance.
======================================================================= ===================================================================

Redefinitions
#############
========================================= =
:bro:type:`FTP::Info`: :bro:type:`record` 
========================================= =

Events
######
=========================================================== ===============================================
:bro:id:`GridFTP::data_channel_detected`: :bro:type:`event` Raised when a GridFTP data channel is detected.
=========================================================== ===============================================

Functions
#########
========================================================================================= =================================================================
:bro:id:`GridFTP::data_channel_initial_criteria`: :bro:type:`function` :bro:attr:`&redef` The initial criteria used to determine whether to start polling
                                                                                          the connection for the :bro:see:`GridFTP::size_threshold` to have
                                                                                          been exceeded.
========================================================================================= =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: GridFTP::max_time

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``2.0 mins``

   Time during which we check whether a connection's size exceeds the
   :bro:see:`GridFTP::size_threshold`.

.. bro:id:: GridFTP::size_threshold

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1073741824``

   Number of bytes transferred before guessing a connection is a
   GridFTP data channel.

.. bro:id:: GridFTP::skip_data

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Whether to skip further processing of the GridFTP data channel once
   detected, which may help performance.

Events
######
.. bro:id:: GridFTP::data_channel_detected

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Raised when a GridFTP data channel is detected.
   

   :c: The connection pertaining to the GridFTP data channel.

Functions
#########
.. bro:id:: GridFTP::data_channel_initial_criteria

   :Type: :bro:type:`function` (c: :bro:type:`connection`) : :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`

   The initial criteria used to determine whether to start polling
   the connection for the :bro:see:`GridFTP::size_threshold` to have
   been exceeded.  This is called in a :bro:see:`ssl_established` event
   handler and by default looks for both a client and server certificate
   and for a NULL bulk cipher.  One way in which this function could be
   redefined is to make it also consider client/server certificate
   issuer subjects.
   

   :c: The connection which may possibly be a GridFTP data channel.
   

   :returns: true if the connection should be further polled for an
            exceeded :bro:see:`GridFTP::size_threshold`, else false.


