##! The intelligence framework provides a way to store and query IP addresses,
##! and strings (with a subtype).  Metadata can
##! also be associated with the intelligence like for making more informated
##! decisions about matching and handling of intelligence.
#
# TODO: 
#   Comments
#   Better Intel::Item comparison (same_meta)
#   Generate a notice when messed up data is discovered.
#   Complete "net" support as an intelligence type.

@load base/frameworks/notice

module Intel;

export {
	redef enum Log::ID += { LOG };
	
	redef enum Notice::Type += {
		## This notice should be used in all detector scripts to indicate 
		## an intelligence based detection.
		Detection,
	};
	
	type Classification: enum {
		MALICIOUS,
		INFRASTRUCTURE,
		SENSITIVE,
		FRIEND,
		CANARY,
		WHITELIST,
	};

	type SubType: enum {
		URL,
		EMAIL,
		DOMAIN,
		USER_NAME,
		FILE_HASH, # (non hash type specific, md5, sha1, sha256)
		CERT_HASH,
		ASN,
	};
	
	type Info: record {
		ts:      time   &log;
		## This value should be one of: "info", "warn", "error"
		level:   string &log;
		message: string &log;
	};
	
	type MetaData: record {
		source:      string;
		class:       Classification;
		desc:        string      &optional;
		url:         string      &optional;
		tags:        set[string] &optional;
	};
	
	type Item: record {
		ip:          addr           &optional;
		net:         subnet         &optional;

		str:         string         &optional;
		subtype:     SubType        &optional;
		
		meta:        MetaData;
	};

	type Query: record {
		ip:          addr           &optional;

		str:         string         &optional;
		subtype:     SubType        &optional;
		
		class:       Classification &optional;

		or_tags:     set[string]    &optional;
		and_tags:    set[string]    &optional;
		
		## The predicate can be given when searching for a match.  It will
		## be tested against every :bro:type:`MetaData` item associated with 
		## the data being matched on.  If it returns T a single time, the 
		## matcher will consider that the item has matched.
		pred:        function(meta: Intel::Item): bool &optional;
	};
	
	type Importer: enum {
		NULL_IMPORTER
	};

	global insert: function(item: Item): bool;
	global insert_event: event(item: Item);
	global delete_item: function(item: Item): bool;

	global matcher: function(query: Query): bool;
	global lookup: function(query: Query): set[Item];

	global register_custom_matcher: function(subtype: SubType, 
	                                         func: function(query: Query): bool);
	global register_custom_lookup: function(subtype: SubType,
	                                        func: function(query: Query): set[Item]);

	global new_item: event(item: Item);
	global updated_item: event(item: Item);
}

## Store collections of :bro:type:`MetaData` records indexed by a source name.
type IndexedItems: table[string, Classification] of MetaData;
type DataStore: record {
	ip_data:     table[addr] of IndexedItems;
	string_data: table[string, SubType] of IndexedItems;
};
global data_store: DataStore;

global custom_matchers: table[SubType] of set[function(query: Query): bool];
global custom_lookup: table[SubType] of set[function(query: Query): set[Item]];

event bro_init() &priority=5
	{
	Log::create_stream(Intel::LOG, [$columns=Info]);
	}

function register_custom_matcher(subtype: SubType, func: function(query: Query): bool)
	{
	if ( subtype !in custom_matchers )
		custom_matchers[subtype] = set();
	add custom_matchers[subtype][func];
	}

function register_custom_lookup(subtype: SubType, func: function(query: Query): set[Item])
	{
	if ( subtype !in custom_lookup )
		custom_lookup[subtype] = set();
	add custom_lookup[subtype][func];
	}



function same_meta(meta1: MetaData, meta2: MetaData): bool
	{
	# "any" type values can't be compared so this generic implementation doesn't work.
	#local rf1 = record_fields(item1);
	#local rf2 = record_fields(item2);
	#for ( field in rf1 )
	#	{
	#	if ( ((rf1[field]?$value && rf1[field]?$value) &&
	#	       rf1[field]$value != rf2[field]$value) ||
	#	      ! (rf1[field]?$value && rf1[field]?$value) )
	#		return F; 
	#	}

	if ( meta1$source == meta2$source &&
	     meta1$class  == meta2$class &&
	     ((!meta1?$desc && !meta2?$desc) || (meta1?$desc && meta2?$desc && meta1$desc == meta2$desc)) &&
	     ((!meta1?$url && !meta2?$url) || (meta1?$url && meta2?$url && meta1$url == meta2$url)) &&
	     ((!meta1?$tags && !meta2?$tags) || (meta1?$tags && meta2?$tags && |meta1$tags| == |meta2$tags|)) )
		{
		# TODO: match on all of the tag values
		return T;
		}

	# The records must not be equivalent if we made it this far.
	return F;
	}

function insert(item: Item): bool
	{
	local err_msg = "";
	if ( item?$str && ! item?$subtype )
		err_msg = "You must provide a subtype for strings or this item doesn't make sense.";
	
	if ( err_msg == "" )
		{
		# Create and fill out the meta data item.
		local meta = item$meta;

		if ( item?$ip )
			{
			if ( item$ip !in data_store$ip_data )
				data_store$ip_data[item$ip] = table();
			
			if ( [meta$source, meta$class] !in data_store$ip_data[item$ip] )
				event Intel::new_item(item);
			else if ( ! same_meta(data_store$ip_data[item$ip][meta$source, meta$class], meta) )
				event Intel::updated_item(item);
			else 
				return F;

			data_store$ip_data[item$ip][meta$source, meta$class] = item$meta;
			return T;
			}
		else if ( item?$str )
			{
			if ( [item$str, item$subtype] !in data_store$string_data )
				data_store$string_data[item$str, item$subtype] = table();
			
			if ( [meta$source, meta$class] !in data_store$string_data[item$str, item$subtype] )
				event Intel::new_item(item);
			else if ( ! same_meta(data_store$string_data[item$str, item$subtype][meta$source, meta$class], meta) )
				event Intel::updated_item(item);
			else 
				return F;

			data_store$string_data[item$str, item$subtype][meta$source, meta$class] = item$meta;
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

function match_item_with_query(item: Item, query: Query): bool
	{
	if ( ! query?$and_tags && ! query?$or_tags && ! query?$pred )
		return T;

	if ( query?$and_tags )
		{
		local matched = T;
		# Every tag given has to match in a single MetaData entry.
		for ( tag in query$and_tags )
			{
			if ( item$meta?$tags && tag !in item$meta$tags )
				matched = F;
			}
		if ( matched )
			return T;
		}
	else if ( query?$or_tags )
		{
		# For OR tags, only a single tag has to match.
		for ( tag in query$or_tags )
			{
			if ( item$meta?$tags && tag in item$meta$tags )
				return T;
			}
		}
	else if ( query?$pred )
		return query$pred(item);

	# This indicates some sort of failure in the query
	return F;
	}
	
function lookup(query: Query): set[Item]
	{
	local meta: MetaData;
	local item: Item;
	local return_data: set[Item] = set();

	if ( query?$ip )
		{
		if ( query$ip in data_store$ip_data )
			{
			for ( [source, class] in data_store$ip_data[query$ip] )
				{
				meta = data_store$ip_data[query$ip][source, class];
				item = [$ip=query$ip,$meta=meta];
				if ( match_item_with_query(item, query) )
					add return_data[item];
				}
			}
		}
	
	else if ( query?$str )
		{
		if ( [query$str, query$subtype] in data_store$string_data )
			{
			for ( [source, class] in data_store$string_data[query$str, query$subtype] )
				{
				meta = data_store$string_data[query$str, query$subtype][source, class];
				item = [$str=query$str,$subtype=query$subtype,$meta=meta];
				if ( match_item_with_query(item, query) )
					add return_data[item];
				}
			}

		# Check if there are any custom subtype lookup functons and add the values to 
		# the result set.
		if ( query$subtype in custom_lookup )
			{
			for ( lookup_func in custom_lookup[query$subtype] )
				{
				# Iterating here because there is no way to merge sets generically.
				for ( custom_lookup_item in lookup_func(query) )
					add return_data[custom_lookup_item];
				}
			}
		}
	
	return return_data;
	}

	
function matcher(query: Query): bool
	{
	local err_msg = "";
	if ( (query?$or_tags || query?$and_tags) && query?$pred )
		err_msg = "You can't match with both tags and a predicate.";
	else if ( query?$or_tags && query?$and_tags )
		err_msg = "You can't match with both OR'd together tags and AND'd together tags";
	else if ( query?$str && ! query?$subtype )
		err_msg = "You must provide a subtype to matcher or this query doesn't make sense.";
		
	local item: Item;
	local meta: MetaData;

	if ( err_msg == "" )
		{
		if ( query?$ip )
			{
			if ( query$ip in data_store$ip_data )
				{
				if ( ! query?$and_tags && ! query?$or_tags && ! query?$pred )
					return T;
				
				for ( [source, class] in data_store$ip_data[query$ip] )
					{
					meta = data_store$ip_data[query$ip][source, class];
					item = [$ip=query$ip,$meta=meta];
					if ( match_item_with_query(item, query) )
						return T;
					}
				}
			}
		
		else if ( query?$str )
			{
			if ( [query$str, query$subtype] in data_store$string_data )
				{
				if ( ! query?$and_tags && ! query?$or_tags && ! query?$pred )
					return T;

				for ( [source, class] in data_store$string_data[query$str, query$subtype] )
					{
					meta = data_store$string_data[query$str, query$subtype][source, class];
					item = [$str=query$str,$subtype=query$subtype,$meta=meta];
					if ( match_item_with_query(item, query) )
						return T;
					}
				}

			# Check if there are any custom subtype matchers in case we haven't matched yet.
			if ( query$subtype in custom_matchers )
				{
				for ( match_func in custom_matchers[query$subtype] )
					{
					if ( match_func(query) )
						return T;
					}
				}
			}

		else
			err_msg = "You must supply one of the $ip or $str fields to search on";
		}
		
	if ( err_msg != "" )
		Log::write(Intel::LOG, [$ts=network_time(), $level="error", $message=fmt(err_msg)]);
	return F;
	}

module GLOBAL;

function INTEL(item: Intel::Query): bool
	{
	return Intel::matcher(item);
	}