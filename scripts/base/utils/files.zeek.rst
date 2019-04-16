:tocdepth: 3

base/utils/files.zeek
=====================


:Imports: :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`

Summary
~~~~~~~
Functions
#########
========================================================================= ======================================================================
:bro:id:`extract_filename_from_content_disposition`: :bro:type:`function` For CONTENT-DISPOSITION headers, this function can be used to extract
                                                                          the filename.
:bro:id:`generate_extraction_filename`: :bro:type:`function`              This function can be used to generate a consistent filename for when
                                                                          contents of a file, stream, or connection are being extracted to disk.
========================================================================= ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: extract_filename_from_content_disposition

   :Type: :bro:type:`function` (data: :bro:type:`string`) : :bro:type:`string`

   For CONTENT-DISPOSITION headers, this function can be used to extract
   the filename.

.. bro:id:: generate_extraction_filename

   :Type: :bro:type:`function` (prefix: :bro:type:`string`, c: :bro:type:`connection`, suffix: :bro:type:`string`) : :bro:type:`string`

   This function can be used to generate a consistent filename for when
   contents of a file, stream, or connection are being extracted to disk.


