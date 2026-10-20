:tocdepth: 3

base/bif/plugins/Zeek_ZIP.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================= ============================================================================================
:zeek:id:`zip_analyzer_stats`: :zeek:type:`event` Generated when the ZIP support analyzer is done forwarding data, once per analyzer that sees
                                                  compressed traffic.
================================================= ============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: zip_analyzer_stats
   :source-code: base/misc/zip-analyzer-limit.zeek 5 8

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, aid: :zeek:type:`count`, total_in: :zeek:type:`count`, total_out: :zeek:type:`count`, exceeded: :zeek:type:`bool`)

   Generated when the ZIP support analyzer is done forwarding data, once per analyzer that sees
   compressed traffic. This is not a ZIP file analyzer, instead used by some analyzers (HTTP, IRC)
   for compressed content.
   

   :param c: The connection.
   

   :param aid: The analyzer identifier of the ZIP analyzer.
   

   :param total_in: The total number of compressed input bytes handled by the ZIP analyzer.
   

   :param total_out: The total number of uncompressed output bytes handled by the ZIP analyzer. This is
              capped if the limit is exceeded.
   

   :param exceeded: True if this stream exceeded either :zeek:see:`HTTP::max_uncompressed_size` or
             :zeek:see:`IRC::max_uncompressed_size`, depending on the parent analyzer. If so,
             total_out will not exceed that cap. False if the cap was not exceeded.


