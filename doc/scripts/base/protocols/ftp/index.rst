:orphan:

Package: base/protocols/ftp
===========================

Support for File Transfer Protocol (FTP) analysis.

:doc:`/scripts/base/protocols/ftp/__load__.zeek`


:doc:`/scripts/base/protocols/ftp/utils-commands.zeek`


:doc:`/scripts/base/protocols/ftp/info.zeek`

   Defines data structures for tracking and logging FTP sessions.

:doc:`/scripts/base/protocols/ftp/main.zeek`

   The logging this script does is primarily focused on logging FTP commands
   along with metadata.  For example, if files are transferred, the argument
   will take on the full path that the client is at along with the requested
   file name.

:doc:`/scripts/base/protocols/ftp/utils.zeek`

   Utilities specific for FTP processing.

:doc:`/scripts/base/protocols/ftp/files.zeek`


:doc:`/scripts/base/protocols/ftp/gridftp.zeek`

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

