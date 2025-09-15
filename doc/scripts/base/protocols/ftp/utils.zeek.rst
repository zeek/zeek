:tocdepth: 3

base/protocols/ftp/utils.zeek
=============================
.. zeek:namespace:: FTP

Utilities specific for FTP processing.

:Namespace: FTP
:Imports: :doc:`base/protocols/ftp/info.zeek </scripts/base/protocols/ftp/info.zeek>`, :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`

Summary
~~~~~~~
Functions
#########
==================================================== ===========================================================
:zeek:id:`FTP::build_url`: :zeek:type:`function`     Creates a URL from an :zeek:type:`FTP::Info` record.
:zeek:id:`FTP::build_url_ftp`: :zeek:type:`function` Creates a URL from an :zeek:type:`FTP::Info` record.
:zeek:id:`FTP::describe`: :zeek:type:`function`      Create an extremely shortened representation of a log line.
==================================================== ===========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: FTP::build_url
   :source-code: base/protocols/ftp/utils.zeek 28 38

   :Type: :zeek:type:`function` (rec: :zeek:type:`FTP::Info`) : :zeek:type:`string`

   Creates a URL from an :zeek:type:`FTP::Info` record.
   

   :param rec: An :zeek:type:`FTP::Info` record.
   

   :returns: A URL, not prefixed by ``"ftp://"``.

.. zeek:id:: FTP::build_url_ftp
   :source-code: base/protocols/ftp/utils.zeek 40 43

   :Type: :zeek:type:`function` (rec: :zeek:type:`FTP::Info`) : :zeek:type:`string`

   Creates a URL from an :zeek:type:`FTP::Info` record.
   

   :param rec: An :zeek:type:`FTP::Info` record.
   

   :returns: A URL prefixed with ``"ftp://"``.

.. zeek:id:: FTP::describe
   :source-code: base/protocols/ftp/utils.zeek 45 48

   :Type: :zeek:type:`function` (rec: :zeek:type:`FTP::Info`) : :zeek:type:`string`

   Create an extremely shortened representation of a log line.


