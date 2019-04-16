:tocdepth: 3

base/files/extract/main.zeek
============================
.. bro:namespace:: FileExtract


:Namespace: FileExtract
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================== ================================================================
:bro:id:`FileExtract::default_limit`: :bro:type:`count` :bro:attr:`&redef` The default max size for extracted files (they won't exceed this
                                                                           number of bytes).
========================================================================== ================================================================

Redefinable Options
###################
==================================================================== ========================================
:bro:id:`FileExtract::prefix`: :bro:type:`string` :bro:attr:`&redef` The prefix where files are extracted to.
==================================================================== ========================================

Redefinitions
#############
====================================================================== =
:bro:type:`Files::AnalyzerArgs`: :bro:type:`record` :bro:attr:`&redef` 
:bro:type:`Files::Info`: :bro:type:`record` :bro:attr:`&redef`         
====================================================================== =

Functions
#########
====================================================== =============================================
:bro:id:`FileExtract::set_limit`: :bro:type:`function` Sets the maximum allowed extracted file size.
====================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: FileExtract::default_limit

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``104857600``

   The default max size for extracted files (they won't exceed this
   number of bytes). A value of zero means unlimited.

Redefinable Options
###################
.. bro:id:: FileExtract::prefix

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"./extract_files/"``

   The prefix where files are extracted to.

Functions
#########
.. bro:id:: FileExtract::set_limit

   :Type: :bro:type:`function` (f: :bro:type:`fa_file`, args: :bro:type:`Files::AnalyzerArgs`, n: :bro:type:`count`) : :bro:type:`bool`

   Sets the maximum allowed extracted file size.
   

   :f: A file that's being extracted.
   

   :args: Arguments that identify a file extraction analyzer.
   

   :n: Allowed number of bytes to be extracted.
   

   :returns: false if a file extraction analyzer wasn't active for
            the file, else true.


