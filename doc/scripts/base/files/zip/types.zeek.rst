:tocdepth: 3

base/files/zip/types.zeek
=========================
.. zeek:namespace:: ZIP

Types used by the Zip file analyzer plugin

:Namespace: ZIP

Summary
~~~~~~~
Types
#####
====================================================== ================================
:zeek:type:`ZIP::CompressionMethod`: :zeek:type:`enum` Compression methods used by Zip.
====================================================== ================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: ZIP::CompressionMethod
   :source-code: base/files/zip/types.zeek 8 12

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ZIP::Uncompressed ZIP::CompressionMethod

         (present if :doc:`/scripts/base/files/zip/types.zeek` is loaded)


      .. zeek:enum:: ZIP::Deflate ZIP::CompressionMethod

         (present if :doc:`/scripts/base/files/zip/types.zeek` is loaded)


   Compression methods used by Zip. Only the methods that Zeek supports for
   content analysis are defined.


