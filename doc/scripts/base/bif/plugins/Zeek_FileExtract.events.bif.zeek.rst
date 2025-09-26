:tocdepth: 3

base/bif/plugins/Zeek_FileExtract.events.bif.zeek
=================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================== ================================================================
:zeek:id:`file_extraction_limit`: :zeek:type:`event` This event is generated when a file extraction analyzer is about
                                                     to exceed the maximum permitted file size allowed by the
                                                     *extract_limit* field of :zeek:see:`Files::AnalyzerArgs`.
==================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: file_extraction_limit
   :source-code: base/files/extract/main.zeek 89 93

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, args: :zeek:type:`Files::AnalyzerArgs`, limit: :zeek:type:`count`, len: :zeek:type:`count`)

   This event is generated when a file extraction analyzer is about
   to exceed the maximum permitted file size allowed by the
   *extract_limit* field of :zeek:see:`Files::AnalyzerArgs`.
   The analyzer is automatically removed from file *f*.
   

   :param f: The file.
   

   :param args: Arguments that identify a particular file extraction analyzer.
         This is only provided to be able to pass along to
         :zeek:see:`FileExtract::set_limit`.
   

   :param limit: The limit, in bytes, the extracted file is about to breach.
   

   :param len: The length of the file chunk about to be written.
   
   .. zeek:see:: Files::add_analyzer Files::ANALYZER_EXTRACT


