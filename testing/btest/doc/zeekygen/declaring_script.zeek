# @TEST-DOC: Test zeekygen declaring script functions. A bit quirky: The path returned for additional scripts depends on whether loaded relative or absolute. We load %INPUT relative here to have relative paths.
#
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek -b `basename %INPUT` >out
# @TEST-EXEC: btest-diff out

@load ./my-module
@load ./redef-it
@load ./pkg1

@load base/protocols/conn
@load protocols/conn/speculative-service
@load protocols/conn/mac-logging

event zeek_init()
	{
	print "Conn::Info", get_identifier_declaring_script("Conn::Info");
	print "Conn::Info$uid", get_record_field_declaring_script("Conn::Info$uid");
	print "Conn::Info$speculative_service", get_record_field_declaring_script("Conn::Info$speculative_service");
	print "Conn::Info$orig_l2_addr", get_record_field_declaring_script("Conn::Info$orig_l2_addr");

	# Custom record
	local record_type_name = "MyModule::Info";
	local record_script = get_identifier_declaring_script(record_type_name);
	print record_type_name, record_script;

	for ( field in record_fields(record_type_name) )
		{
		local field_identifier = fmt("%s$%s", record_type_name, field);
		local field_script = get_record_field_declaring_script(field_identifier);
		print field_identifier, record_script != field_script ? "redef" : "original", field_script;
		}
	}


@TEST-START-FILE my-module.zeek
module MyModule;

export {
	type Info: record {
		ts: time &log;
		prefix: string &log;
	};
}

@TEST-END-FILE


@TEST-START-FILE redef-it.zeek
module RedefIt;

export {
	redef record MyModule::Info += {
		addl: string &log &default="dfl";
	};
}
@TEST-END-FILE

@TEST-START-FILE pkg1/__load__.zeek
@load ./redef-more.zeek
@TEST-END-FILE


@TEST-START-FILE pkg1/redef-more.zeek
module RedefMore;

export {
	redef record MyModule::Info += {
		more: string &log &default="more";
	};
}
@TEST-END-FILE
