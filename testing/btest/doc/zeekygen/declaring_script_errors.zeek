# @TEST-DOC: Test zeekygen declaring script functions error/empty cases.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek -b `basename %INPUT` >out
# @TEST-EXEC: btest-diff out

@load base/protocols/conn

event zeek_init()
	{
	print "get_identifier_declaring_script(\"\")", to_json(get_identifier_declaring_script(""));
	print "get_identifier_declaring_script(\"UnknownRecord\")", to_json(get_identifier_declaring_script("UnknownRecord"));
	print "get_record_field_declaring_script(\"\")", to_json(get_record_field_declaring_script(""));
	print "get_record_field_declaring_script(\"UnknownRecord\")", to_json(get_record_field_declaring_script("UnknownRecord"));
	print "get_record_field_declaring_script(\"Conn$\")", to_json(get_record_field_declaring_script("Conn$"));
	print "get_record_field_declaring_script(\"Conn$unknown_field\")", to_json(get_record_field_declaring_script("Conn$unknown_field"));
	}
