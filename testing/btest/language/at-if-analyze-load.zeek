# @TEST-EXEC: zeek -b %INPUT > out 2>&1
# @TEST-EXEC: btest-diff out

@TEST-START-FILE mod.zeek
module MyModule;

export {
	global version: function(): string;
}

function version(): string {
	return "1.23";
}
@TEST-END-FILE

@if ( F ) &analyze
@load ./mod.zeek
@endif

@load ./mod.zeek

event zeek_init()
	{
	print MyModule::version();
	}
