# @TEST-DOC: redef of ::type works when global type is shadowed by module.

# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

module MyModule;

# Module private connection type.
type connection: record { };

# Redefing the moduleconnection record.
redef record connection += {
	y: count &optional;
};

# Redefing the global connection record.
redef record ::connection += {
	x: count &optional;
};

event zeek_init()
	{
	print "connection", connection, record_fields(connection);
	print "::connection", ::connection, record_fields(::connection)["x"];
	}
