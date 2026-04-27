# @TEST-DOC: Test ZIP analyzer with a ZIP containing a pdf, exe, png and webp file
#
# @TEST-EXEC: zeek -Cr ${TRACES}/zip/a.zip.pcap
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid fuid mime_type source filename extracted extracted_size files.log

@load base/files/zip
