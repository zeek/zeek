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
#   file_md5
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
	
	redef enum Notice::Type += {
		## This notice should be used in all detector scripts to indicate 
		## an intelligence based detection.
		Detection,
	};
	
	type Info: record {
		ts:      time   &log;
		## This value should be one of: "info", "warn", "error"
		level:   string &log;
		message: string &log;
	};
	
	type MetaData: record {
		desc:        string      &optional;
		url:         string      &optional;
		first_seen:  time        &optional;
		latest_seen: time        &optional;
		tags:        set[string];
	};
	
	type Item: record {
		ip:          addr        &optional;
		str:         string      &optional;
		num:         int         &optional;
		subtype:     string      &optional;
		
		desc:        string      &optional;
		url:         string      &optional;
		first_seen:  time        &optional;
		latest_seen: time        &optional;
		tags:        set[string];
		
		## These single string tags are throw away until pybroccoli supports sets
		tag1: string &optional;
		tag2: string &optional;
		tag3: string &optional;
	};
	
	type QueryItem: record {
		ip:          addr        &optional;
		str:         string      &optional;
		num:         int         &optional;
		subtype:     string      &optional;
		
		or_tags:     set[string] &optional;
		and_tags:    set[string] &optional; 
		
		## The predicate can be given when searching for a match.  It will
		## be tested against every :bro:type:`MetaData` item associated with 
		## the data being matched on.  If it returns T a single time, the 
		## matcher will consider that the item has matched.
		pred:    function(meta: Intel::MetaData): bool &optional;
	};
	
	
	global insert: function(item: Item): bool;
	global insert_event: event(item: Item);
	global matcher: function(item: QueryItem): bool;

	type MetaDataStore: table[count] of MetaData;
	type DataStore: record {
		ip_data:     table[addr] of MetaDataStore;
		## The first string is the actual value and the second string is the subtype.
		string_data: table[string, string] of MetaDataStore;
		int_data:    table[int, string] of MetaDataStore;
	};
	global data_store: DataStore;


}

event bro_init()
	{
	Log::create_stream(INTEL, [$columns=Info]);
	}


function insert(item: Item): bool
	{
	local err_msg = "";
	if ( (item?$str || item?$num) && ! item?$subtype )
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
		if ( item?$url )
			meta$url = item$url;
		
		
		# This is hopefully only temporary until pybroccoli supports sets.
		if ( item?$tag1 )
			add item$tags[item$tag1];
		if ( item?$tag2 )
			add item$tags[item$tag2];
		if ( item?$tag3 )
			add item$tags[item$tag3];
		
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
	
event insert_event(item: Item)
	{
	insert(item);
	}
	
function match_item_with_metadata(item: QueryItem, meta: MetaData): bool
	{
	if ( item?$and_tags )
		{
		local matched = T;
		# Every tag given has to match in a single MetaData entry.
		for ( tag in item$and_tags )
			{
			if ( tag !in meta$tags )
				matched = F;
			}
		if ( matched )
			return T;
		}
	else if ( item?$or_tags )
		{
		# For OR tags, only a single tag has to match.
		for ( tag in item$or_tags )
			{
			if ( tag in meta$tags )
				return T;
			}
		}
	else if ( item?$pred )
		return item$pred(meta);

	# This indicates some sort of failure in the query
	return F;
	}
	
function matcher(item: QueryItem): bool
	{
	local err_msg = "";
	if ( ! (item?$ip || item?$str || item?$num) )
		err_msg = "You must supply one of the $ip, $str, or $num fields to search on";
	else if ( (item?$or_tags || item?$and_tags) && item?$pred )
		err_msg = "You can't match with both tags and a predicate.";
	else if ( item?$or_tags && item?$and_tags )
		err_msg = "You can't match with both OR'd together tags and AND'd together tags";
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
				if ( ! item?$and_tags && ! item?$or_tags && ! item?$pred )
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
				if ( ! item?$and_tags && ! item?$or_tags && ! item?$pred )
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
				if ( ! item?$and_tags && ! item?$or_tags && ! item?$pred )
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
