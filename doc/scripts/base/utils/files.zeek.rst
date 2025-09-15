:tocdepth: 3

base/utils/files.zeek
=====================


:Imports: :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`

Summary
~~~~~~~
Functions
#########
=========================================================================== ======================================================================
:zeek:id:`extract_filename_from_content_disposition`: :zeek:type:`function` For CONTENT-DISPOSITION headers, this function can be used to extract
                                                                            the filename.
:zeek:id:`generate_extraction_filename`: :zeek:type:`function`              This function can be used to generate a consistent filename for when
                                                                            contents of a file, stream, or connection are being extracted to disk.
=========================================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: extract_filename_from_content_disposition
   :source-code: base/utils/files.zeek 20 33

   :Type: :zeek:type:`function` (data: :zeek:type:`string`) : :zeek:type:`string`

   For CONTENT-DISPOSITION headers, this function can be used to extract
   the filename.

.. zeek:id:: generate_extraction_filename
   :source-code: base/utils/files.zeek 5 16

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, c: :zeek:type:`connection`, suffix: :zeek:type:`string`) : :zeek:type:`string`

   This function can be used to generate a consistent filename for when
   contents of a file, stream, or connection are being extracted to disk.


