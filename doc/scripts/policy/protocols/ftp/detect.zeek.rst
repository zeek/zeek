:tocdepth: 3

policy/protocols/ftp/detect.zeek
================================
.. zeek:namespace:: FTP

Detect various potentially bad FTP activities.

:Namespace: FTP
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ftp </scripts/base/protocols/ftp/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =======================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`FTP::Site_Exec_Success`:
                                               Indicates that a successful response to a "SITE EXEC"
                                               command/arg pair was seen.
============================================ =======================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

