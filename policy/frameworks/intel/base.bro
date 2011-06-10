##! The intelligence framework provides a way to store and query IP addresses,
##! strings (with a subtype), and numeric (with a subtype) data.  Metadata 
##! also be associated with the intelligence like tags which are arbitrary
##! strings, time values, and longer descriptive strings.

# Example string subtypes:
#   url
#   email
#   domain
#   software
#   user_name
#   file_name
#   file_md5sum
#   x509_cert - DER encoded, not PEM (ascii armored)

# Example tags: 
#   infrastructure
#   malicious
#   sensitive
#   canary
#   friend

module Intel;

export {
	redef enum Log::ID += { INTEL };
	
	type Info: record {
		ts:      time   &log;
		## This value should be one of: "info", "warn", "error"
		level:   string &log;
		message: string &log;
	};
	
	type MetaData: record {
		desc:        string      &optional;
		first_seen:  time        &optional;
		latest_seen: time        &optional;
		tags:        set[string];
	};
	
	type MetaDataStore: table[count] of MetaData;
	
	type Item: record {
		ip:          addr        &optional;
		str:         string      &optional;
		num:         int         &optional;
		subtype:     string      &optional;
		
		desc:        string      &optional;
		first_seen:  time        &optional;
		latest_seen: time        &optional;
		tags:        set[string] &optional;
		
		## The predicate can be given when searching for a match.  It will
		## be tested against every :bro:type:`MetaData` item associated with 
		## the data being matched on.  If it returns T a single time, the 
		## matcher will consider that the item has matched.
		pred:    function(meta: Intel::MetaData): bool &optional;
	};
	
	global insert: event(item: Item);
	global insert_sync: function(item: Item): bool;
	global matcher: function(item: Item): bool;
	
}

event bro_init()
	{
	Log::create_stream(INTEL, [$columns=Info]);
	}

type DataStore: record {
	ip_data:     table[addr] of MetaDataStore;
	## The first string is the actual value and the second string is the subtype.
	string_data: table[string, string] of MetaDataStore;
	int_data:    table[int, string] of MetaDataStore;
};
global data_store: DataStore;

function insert_sync(item: Item): bool
	{
	local err_msg = "";
	
	if ( item?$pred )
		err_msg = "Intel::Items should not have the $pred field when calling insert_sync() or insert()";
	else if ( (item?$str || item?$num) && ! item?$subtype )
		err_msg = "You must provide a subtype to insert_sync or this item doesn't make sense.";
	
	if ( err_msg == "" )
		{
		# Create and fill out the meta data item.
		local meta: MetaData;
		if ( item?$first_seen )
			meta$first_seen = item$first_seen;
		if ( item?$latest_seen )
			meta$latest_seen = item$latest_seen;
		if ( item?$tags )
			meta$tags = item$tags;
		if ( item?$desc )
			meta$desc = item$desc;
	
		if ( item?$ip )
			{
			if ( item$ip !in data_store$ip_data )
				data_store$ip_data[item$ip] = table();
			data_store$ip_data[item$ip][|data_store$ip_data[item$ip]|] = meta;
			return T;
			}
		else if ( item?$str )
			{
			if ( [item$str, item$subtype] !in data_store$string_data )
				data_store$string_data[item$str, item$subtype] = table();
			
			data_store$string_data[item$str, item$subtype][|data_store$string_data[item$str, item$subtype]|] = meta;
			return T;
			}
		else if ( item?$num )
			{
			if ( [item$num, item$subtype] !in data_store$int_data )
				data_store$int_data[item$num, item$subtype] = table();

			data_store$int_data[item$num, item$subtype][|data_store$int_data[item$num, item$subtype]|] = meta;
			return T;
			}
		else
			err_msg = "Failed to insert intelligence item for some unknown reason.";
		}
	
	if ( err_msg != "" )
		Log::write(INTEL, [$ts=network_time(), $level="warn", $message=fmt(err_msg)]);
	return F;
	}
	
event insert(item: Item)
	{
	insert_sync(item);
	}
	
function match_item_with_metadata(item: Item, meta: MetaData): bool
	{
	if ( item?$tags )
		{
		local matched = T;
		# Every tag given has to match in a single MetaData entry.
		for ( tag in item$tags )
			{
			if ( tag !in meta$tags )
				matched = F;
			}
		if ( matched )
			return T;
		}
	else if ( item?$pred )
		{
		if ( item$pred(meta) )
			return T;
		}
	return F;
	}
	
function matcher(item: Item): bool
	{
	local err_msg = "";
	if ( ! (item?$ip || item?$str || item?$num) )
		err_msg = "You must supply one of the $ip, $str, or $num fields to search on";
	else if ( item?$tags && item?$pred )
		err_msg = "You can't match with both tags and a predicate.";
	else if ( (item?$str || item?$num) && ! item?$subtype )
		err_msg = "You must provide a subtype to matcher or this item doesn't make sense.";
	else if ( item?$str && item?$num )
		err_msg = "You must only provide $str or $num, not both.";
		
	local meta: MetaData;

	if ( err_msg == "" )
		{
		if ( item?$ip )
			{
			if ( item$ip in data_store$ip_data )
				{
				if ( ! item?$tags && ! item?$pred )
					return T;
			
				for ( i in data_store$ip_data[item$ip] )
					{
					meta = data_store$ip_data[item$ip][i];
					if ( match_item_with_metadata(item, meta) )
						return T;
					}
				}
			}
		
		else if ( item?$str )
			{
			if ( [item$str, item$subtype] in data_store$string_data )
				{
				if ( ! item?$tags && ! item?$pred )
					return T;

				for ( i in data_store$string_data[item$str, item$subtype] )
					{
					meta = data_store$string_data[item$str, item$subtype][i];
					if ( match_item_with_metadata(item, meta) )
						return T;
					}
				}
			}
		
		else if ( item?$num )
			{
			if ( [item$num, item$subtype] in data_store$int_data )
				{
				if ( ! item?$tags && ! item?$pred )
					return T;

				for ( i in data_store$int_data[item$num, item$subtype] )
					{
					meta = data_store$int_data[item$num, item$subtype][i];
					if ( match_item_with_metadata(item, meta) )
						return T;
					}
				}
			}
		else
			err_msg = "Failed to query intelligence data for some unknown reason.";
		}
		
	if ( err_msg != "" )
		Log::write(INTEL, [$ts=network_time(), $level="error", $message=fmt(err_msg)]);
	return F;
	}
