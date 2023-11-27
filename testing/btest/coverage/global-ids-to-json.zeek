# @TEST-DOC: Ensure to_json(global_ids()) does not abort and do not expect any stderr output.
# @TEST-EXEC: unset ZEEK_ALLOW_INIT_ERRORS; zeek %INPUT
# @TEST-EXEC: btest-diff .stderr

event zeek_init()
	{
	assert |to_json(global_ids())| > 0;
	}
