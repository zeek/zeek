# @TEST-DOC: Test ZIP analyzer with a ZIP containing a pdf, exe, png and webp file
#
# @TEST-EXEC: zeek -Cr ${TRACES}/zip/a.zip.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid fuid parent_fuid source filename mime_type seen_bytes total_bytes missing_bytes files.log

@load base/files/zip
@load policy/files/zip/register
