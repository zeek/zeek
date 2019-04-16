:tocdepth: 3

base/protocols/ftp/utils.zeek
=============================
.. bro:namespace:: FTP

Utilities specific for FTP processing.

:Namespace: FTP
:Imports: :doc:`base/protocols/ftp/info.zeek </scripts/base/protocols/ftp/info.zeek>`, :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`

Summary
~~~~~~~
Functions
#########
================================================== ===========================================================
:bro:id:`FTP::build_url`: :bro:type:`function`     Creates a URL from an :bro:type:`FTP::Info` record.
:bro:id:`FTP::build_url_ftp`: :bro:type:`function` Creates a URL from an :bro:type:`FTP::Info` record.
:bro:id:`FTP::describe`: :bro:type:`function`      Create an extremely shortened representation of a log line.
================================================== ===========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: FTP::build_url

   :Type: :bro:type:`function` (rec: :bro:type:`FTP::Info`) : :bro:type:`string`

   Creates a URL from an :bro:type:`FTP::Info` record.
   

   :rec: An :bro:type:`FTP::Info` record.
   

   :returns: A URL, not prefixed by ``"ftp://"``.

.. bro:id:: FTP::build_url_ftp

   :Type: :bro:type:`function` (rec: :bro:type:`FTP::Info`) : :bro:type:`string`

   Creates a URL from an :bro:type:`FTP::Info` record.
   

   :rec: An :bro:type:`FTP::Info` record.
   

   :returns: A URL prefixed with ``"ftp://"``.

.. bro:id:: FTP::describe

   :Type: :bro:type:`function` (rec: :bro:type:`FTP::Info`) : :bro:type:`string`

   Create an extremely shortened representation of a log line.


