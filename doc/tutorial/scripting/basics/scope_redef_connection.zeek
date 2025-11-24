module DenyList;

export {
	# Make a deny list to show functionality
    const deny_list: set[addr] = set(192.168.1.8);
}

redef record connection += {
	# Add a boolean field.
	# 
	# &default sets the default value to F. Any ``redef``ed record fields
	#          must have this or ``&optional``
	denied: bool &default=F;
};

event new_connection(c: connection) {
	# The denied flag gets set if one of the IPs is in the deny list
	c$denied = c$id$orig_h in deny_list || c$id$resp_h in deny_list;
	print c$denied;
}
