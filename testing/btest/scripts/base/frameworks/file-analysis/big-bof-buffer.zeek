# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff files.log

@load base/protocols/http
@load base/files/hash
@load base/files/extract
@load frameworks/files/hash-all-files

redef default_file_bof_buffer_size=5000;
