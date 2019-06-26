# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff files.log

@load frameworks/files/hash-all-files

redef default_file_bof_buffer_size=5000;
