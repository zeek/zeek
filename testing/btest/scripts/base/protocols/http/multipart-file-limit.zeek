# @TEST-EXEC: zeek -C -r $TRACES/http/multipart.trace
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: zeek -C -r $TRACES/http/multipart.trace %INPUT >out-limited
# @TEST-EXEC: mv http.log http-limited.log
# @TEST-EXEC: btest-diff http-limited.log
# @TEST-EXEC: btest-diff out-limited
# @TEST-EXEC: zeek -C -r $TRACES/http/multipart.trace %INPUT ignore_http_file_limit=T >out-limit-ignored
# @TEST-EXEC: mv http.log http-limit-ignored.log
# @TEST-EXEC: btest-diff http-limit-ignored.log
# @TEST-EXEC: btest-diff out-limit-ignored

option ignore_http_file_limit = F;

redef HTTP::max_files_orig = 1;
redef HTTP::max_files_resp = 1;

hook HTTP::max_files_policy(f: fa_file, is_orig: bool)
	{
	print "max_files reached";

	if ( ignore_http_file_limit )
		break;
	}
