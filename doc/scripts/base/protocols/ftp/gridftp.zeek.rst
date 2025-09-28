:tocdepth: 3

base/protocols/ftp/gridftp.zeek
===============================
.. zeek:namespace:: GridFTP

A detection script for GridFTP data and control channels.

GridFTP control channels are identified by FTP control channels
that successfully negotiate the GSSAPI method of an AUTH request
and for which the exchange involved an encoded TLS/SSL handshake,
indicating the GSI mechanism for GSSAPI was used.  This analysis
is all supported internally, this script simply adds the "gridftp"
label to the *service* field of the control channel's
:zeek:type:`connection` record.

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
========================================================================== ===================================================================
:zeek:id:`GridFTP::max_time`: :zeek:type:`interval` :zeek:attr:`&redef`    Time during which we check whether a connection's size exceeds the
                                                                           :zeek:see:`GridFTP::size_threshold`.
:zeek:id:`GridFTP::size_threshold`: :zeek:type:`count` :zeek:attr:`&redef` Number of bytes transferred before guessing a connection is a
                                                                           GridFTP data channel.
:zeek:id:`GridFTP::skip_data`: :zeek:type:`bool` :zeek:attr:`&redef`       Whether to skip further processing of the GridFTP data channel once
                                                                           detected, which may help performance.
========================================================================== ===================================================================

Redefinitions
#############
=========================================== =================================================================
:zeek:type:`FTP::Info`: :zeek:type:`record` 
                                            
                                            :New Fields: :zeek:type:`FTP::Info`
                                            
                                              last_auth_requested: :zeek:type:`string` :zeek:attr:`&optional`
=========================================== =================================================================

Events
######
============================================================= ===============================================
:zeek:id:`GridFTP::data_channel_detected`: :zeek:type:`event` Raised when a GridFTP data channel is detected.
============================================================= ===============================================

Functions
#########
============================================================================================ ==================================================================
:zeek:id:`GridFTP::data_channel_initial_criteria`: :zeek:type:`function` :zeek:attr:`&redef` The initial criteria used to determine whether to start polling
                                                                                             the connection for the :zeek:see:`GridFTP::size_threshold` to have
                                                                                             been exceeded.
============================================================================================ ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: GridFTP::max_time
   :source-code: base/protocols/ftp/gridftp.zeek 37 37

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2.0 mins``

   Time during which we check whether a connection's size exceeds the
   :zeek:see:`GridFTP::size_threshold`.

.. zeek:id:: GridFTP::size_threshold
   :source-code: base/protocols/ftp/gridftp.zeek 33 33

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1073741824``

   Number of bytes transferred before guessing a connection is a
   GridFTP data channel.

.. zeek:id:: GridFTP::skip_data
   :source-code: base/protocols/ftp/gridftp.zeek 41 41

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether to skip further processing of the GridFTP data channel once
   detected, which may help performance.

Events
######
.. zeek:id:: GridFTP::data_channel_detected
   :source-code: base/protocols/ftp/gridftp.zeek 46 46

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Raised when a GridFTP data channel is detected.
   

   :param c: The connection pertaining to the GridFTP data channel.

Functions
#########
.. zeek:id:: GridFTP::data_channel_initial_criteria
   :source-code: base/protocols/ftp/gridftp.zeek 108 113

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`) : :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`

   The initial criteria used to determine whether to start polling
   the connection for the :zeek:see:`GridFTP::size_threshold` to have
   been exceeded.  This is called in a :zeek:see:`ssl_established` event
   handler and by default looks for both a client and server certificate
   and for a NULL bulk cipher.  One way in which this function could be
   redefined is to make it also consider client/server certificate
   issuer subjects.
   

   :param c: The connection which may possibly be a GridFTP data channel.
   

   :returns: true if the connection should be further polled for an
            exceeded :zeek:see:`GridFTP::size_threshold`, else false.


