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
#   x509_md5

# Example tags: 
#   infrastructure
#   malicious
#   sensitive
#   canary
#   friend

@load base/frameworks/notice

module Intel;

export {
	## The intel logging stream identifier.
	redef enum Log::ID += { LOG };
	
	redef enum Notice::Type += {
		## This notice should be used in all detector scripts to indicate 
		## an intelligence based detection.
		Detection,
	};
	
	## Record type used for logging information from the intelligence framework.
	## Primarily for problems or oddities with inserting and querying data.  
	## This is important since the content of the intelligence framework can 
	## change quite dramatically during runtime and problems may be introduced 
	## into the data.
	type Info: record {
		## The current network time.
		ts:      time   &log;
		## Represents the severity of the message. 
		## This value should be one of: "info", "warn", "error"
		level:   string &log;
		## The message.
		message: string &log;
	};
	
	## Record to represent metadata associated with a single piece of
	## intelligence.
	type MetaData: record {
		## A description for the data.
		desc:        string      &optional;
		## A URL where more information may be found about the intelligence.
		url:         string      &optional;
		## The time at which the data was first declared to be intelligence.
		first_seen:  time        &optional;
		## When this data was most recent inserted into the framework.
		latest_seen: time        &optional;
		## Arbitrary text tags for the data.
		tags:        set[string];
	};
	
	## Record to represent a singular piece of intelligence.
	type Item: record {
		## If the data is an IP address, this hold the address.
		ip:          addr        &optional;
		## If the data is textual, this holds the text.
		str:         string      &optional;
		## If the data is numeric, this holds the number.
		num:         int         &optional;
		## The subtype of the data for when either the $str or $num fields are
		## given.  If one of those fields are given, this field must be present.
		subtype:     string      &optional;
		
		## The next five fields are temporary until a better model for 
		## attaching metadata to an intelligence item is created.
		desc:        string      &optional;
		url:         string      &optional;
		first_seen:  time        &optional;
		latest_seen: time        &optional;
		tags:        set[string];
		
		## These single string tags are throw away until pybroccoli supports sets.
		tag1: string &optional;
		tag2: string &optional;
		tag3: string &optional;
	};
	
	## Record model used for constructing queries against the intelligence 
	## framework.
	type QueryItem: record {
		## If an IP address is being queried for, this field should be given.
		ip:        addr        &optional;
		## If a string is being queried for, this field should be given.
		str:       string      &optional;
		## If numeric data is being queried for, this field should be given.
		num:       int         &optional;
		## If either a string or number is being queried for, this field should
		## indicate the subtype of the data.
		subtype:   string      &optional;
		
		## A set of tags where if a single metadata record attached to an item
		## has any one of the tags defined in this field, it will match.
		or_tags:   set[string] &optional;
		## A set of tags where a single metadata record attached to an item 
		## must have all of the tags defined in this field.
		and_tags:  set[string] &optional; 
		
		## The predicate can be given when searching for a match.  It will
		## be tested against every :bro:type:`Intel::MetaData` item associated
		## with the data being matched on.  If it returns T a single time, the 
		## matcher will consider that the item has matched.  This field can
		## be used for constructing arbitrarily complex queries that may not
		## be possible with the $or_tags or $and_tags fields.
		pred:      function(meta: Intel::MetaData): bool &optional;
	};
	
	## Function to insert data into the intelligence framework.
	## 
	## item: The data item.
	##
	## Returns: T if the data was successfully inserted into the framework,
	##          otherwise it returns F.
	global insert: function(item: Item): bool;
	
	## A wrapper for the :bro:id:`Intel::insert` function.  This is primarily
	## used as the external API for inserting data into the intelligence 
	## using Broccoli.
	global insert_event: event(item: Item);
	
	## Function for matching data within the intelligence framework.
	global matcher: function(item: QueryItem): bool;
}

type MetaDataStore: table[count] of MetaData;
type DataStore: record {
	ip_data:     table[addr] of MetaDataStore;
	# The first string is the actual value and the second string is the subtype.
	string_data: table[string, string] of MetaDataStore;
	int_data:    table[int, string] of MetaDataStore;
};
global data_store: DataStore;

event bro_init()
	{
	Log::create_stream(Intel::LOG, [$columns=Info]);
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
		Log::write(Intel::LOG, [$ts=network_time(), $level="warn", $message=fmt(err_msg)]);
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
		Log::write(Intel::LOG, [$ts=network_time(), $level="error", $message=fmt(err_msg)]);
	return F;
	}
