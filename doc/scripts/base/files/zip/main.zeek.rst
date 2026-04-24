:tocdepth: 3

base/files/zip/main.zeek
========================
.. zeek:namespace:: ZIP


:Namespace: ZIP

Summary
~~~~~~~
Types
#####
=========================================== =
:zeek:type:`ZIP::File`: :zeek:type:`record`
=========================================== =

Redefinitions
#############
============================================================= =========================================================
:zeek:type:`fa_file`: :zeek:type:`record` :zeek:attr:`&redef`

                                                              :New Fields: :zeek:type:`fa_file`

                                                                zip_file: :zeek:type:`ZIP::File` :zeek:attr:`&optional`
============================================================= =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: ZIP::File
   :source-code: base/files/zip/main.zeek 4 20

   :Type: :zeek:type:`record`


   .. zeek:field:: global_ :zeek:type:`bool`

      True if from global directory header, false if from local file header


   .. zeek:field:: fid :zeek:type:`string` :zeek:attr:`&optional`

      File ID associated with content analysis of this file. Only available for local
      headers where file content has been further processed.


   .. zeek:field:: filename :zeek:type:`string`

      Name of file


   .. zeek:field:: time_ :zeek:type:`time`

      Timestamp of file


   .. zeek:field:: comment :zeek:type:`string`

      Comment associated with file.


   .. zeek:field:: compression :zeek:type:`ZIP::CompressionMethod`

      Compression type


   .. zeek:field:: encrypted :zeek:type:`bool`

      True if encrypted




