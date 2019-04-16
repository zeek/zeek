:tocdepth: 3

base/bif/plugins/Bro_FileExtract.events.bif.zeek
================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================== ================================================================
:bro:id:`file_extraction_limit`: :bro:type:`event` This event is generated when a file extraction analyzer is about
                                                   to exceed the maximum permitted file size allowed by the
                                                   *extract_limit* field of :bro:see:`Files::AnalyzerArgs`.
================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: file_extraction_limit

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, args: :bro:type:`Files::AnalyzerArgs`, limit: :bro:type:`count`, len: :bro:type:`count`)

   This event is generated when a file extraction analyzer is about
   to exceed the maximum permitted file size allowed by the
   *extract_limit* field of :bro:see:`Files::AnalyzerArgs`.
   The analyzer is automatically removed from file *f*.
   

   :f: The file.
   

   :args: Arguments that identify a particular file extraction analyzer.
         This is only provided to be able to pass along to
         :bro:see:`FileExtract::set_limit`.
   

   :limit: The limit, in bytes, the extracted file is about to breach.
   

   :len: The length of the file chunk about to be written.
   
   .. bro:see:: Files::add_analyzer Files::ANALYZER_EXTRACT


