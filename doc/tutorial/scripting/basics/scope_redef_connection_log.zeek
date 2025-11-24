module DenyList;

export {
	# Make a deny list to show functionality
    const deny_list: set[addr] = set(192.168.1.8);
}

redef record Conn::Info += {
	# Add a boolean field.
	# 
	# &log means this field will be logged (in conn.log here)
	# 
	# &default sets the default value to F. Any ``redef``ed record fields
	#          must have this or ``&optional``
	denied: bool &log &default=F;
};

event new_connection(c: connection) {
	# The denied flag gets set if one of the IPs are in the deny list
	c$conn$denied = c$id$orig_h in deny_list || c$id$resp_h in deny_list;
}
