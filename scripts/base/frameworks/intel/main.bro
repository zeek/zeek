##! The intelligence framework provides a way to store and query IP addresses,
##! and strings (with a str_type).  Metadata can
##! also be associated with the intelligence like for making more informated
##! decisions about matching and handling of intelligence.
#
# TODO: 
#   Comments
#   Better Intel::Item comparison (has_meta)
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
	
	## String data needs to be further categoried since it could represent
	## and number of types of data.
	type SubType: enum {
		## A complete URL.
		URL,
		## User-Agent string, typically HTTP or mail message body.
		USER_AGENT,
		## Email address.
		EMAIL,
		## DNS domain name (DNS Zones are implemented in an intelligence plugin).
		DOMAIN,
		## A user name.
		USER_NAME,
		## File hash which is non hash type specific.  It's up to the user to query
		## for any relevant hash types.
		FILE_HASH,
		## Certificate hash.  Normally for X.509 certificates from the SSL analyzer.
		CERT_HASH,
	};

	## Why a piece of intelligence is being added or looked up.  The intent a human
	## placed upon the data when it was decided to be worthwhile as intelligence.
	type Intent: enum {
		## Data is to be considered malicious.
		MALICIOUS,
		## Data is to be considered sensitive.  In many cases this may be
		## hosts containing contractually or legally restricted data such 
		## as HIPPA, PCI, Sarbanes-Oxley, etc.
		SENSITIVE,
		## Data that is never to be seen.  This acts like the "canary in 
		## the coal mine".  A possibility could be file hashes for 
		## critically important files.
		CANARY,
		## Data that is whitelisted.  The primary use for this intent is to 
		## locally whitelist false positive data from external feeds.
		WHITELIST,
	};

	## Enum to represent where data came from when it was discovered.
	type Where: enum {
		## A catchall value to represent data of unknown provenance.
		ANYWHERE,
	};
		
	## Data about an :bro:type:`Intel::Item`
	type MetaData: record {
		## An arbitrary string value representing the data source.  Typically,
		## the convention for this field will be the source name and feed name
		## separated by a hyphen.  For example: "source1-c&c".
		source:      string;
		## The intent of the data.
		intent:      Intent;
		## A freeform description for the data.
		desc:        string      &optional;
		## A URL for more information about the data.
		url:         string      &optional;
	};
	
	type Item: record {
		host:        addr           &optional;
		net:         subnet         &optional;
		str:         string         &optional;
		str_type:    SubType        &optional;
		
		meta:        MetaData;
	};
	
	type Found: record {
		host:      addr          &optional;
		str:       string        &optional;
		str_type:  SubType       &optional;

		where:     Where;
	};

	type Info: record {
		ts:      time   &log;
		## This value should be one of: "info", "warn", "error"
		level:   string &log;
		message: string &log;
		item:    Item   &log;
	};

	type Plugin: record {
		index:  function()                        &optional;
		match:  function(found: Found): bool      &optional;
		lookup: function(found: Found): set[Item] &optional;
	};

	## Manipulation and query API functions.
	global insert:      function(item: Item);
	global delete_item: function(item: Item): bool;
	global unique_data: function(): count;

	## Function to declare discovery of a piece of data in order to check
	## it against known intelligence for matches.
	global found_in_conn:  function(c: connection, found: Found);

	## Event to represent a match happening in a connection.  On clusters there
	## is no assurance as to where this event will be generated so don't 
	## assume that arbitrary global state beyond the given data
	## will be available.
	global match_in_conn: event(c: connection, found: Found, items: set[Item]);

	global find: function(found: Found): bool;
	global lookup: function(found: Found): set[Item];


	## Plugin API functions
	global register_custom_matcher: function(str_type: SubType, 
	                                         func: function(found: Found): bool);
	global register_custom_lookup: function(str_type: SubType,
	                                        func: function(found: Found): set[Item]);

	## API Events
	global new_item: event(item: Item);
	global updated_item: event(item: Item);
	global insert_event: event(item: Item);

	## Optionally store metadata.  This is primarily used internally depending on
	## if this is a cluster deployment or not.  On clusters, workers probably
	## shouldn't be storing the full metadata.
	const store_metadata = T &redef;
}

# Internal handler for conn oriented matches with no metadata base on the store_metadata setting.
global match_in_conn_no_items: event(c: connection, found: Found);

type DataStore: record {
	host_data:   table[addr] of set[MetaData];
	string_data: table[string, SubType] of set[MetaData];
};
global data_store: DataStore;

global custom_matchers: table[SubType] of set[function(found: Found): bool];
global custom_lookup: table[SubType] of set[function(found: Found): set[Item]];


event bro_init() &priority=5
	{
	Log::create_stream(Intel::LOG, [$columns=Info]);
	}


function find(found: Found): bool
	{
	if ( found?$host && found$host in data_store$host_data)
		{
		return T;
		}
	else if ( found?$str && found?$str_type && 
	          [found$str, found$str_type] in data_store$string_data )
		{
		return T;
		}

	# Finder plugins!
	for ( plugin in plugins )
		{
		if ( plugin?$match && plugin$match(found) )
			return T;
		}

	return F;
	}

function lookup(found: Found): set[Item]
	{
	local item: Item;
	local return_data: set[Item] = set();

	if ( found?$host )
		{
		# See if the host is known about and it has meta values
		if ( found$host in data_store$host_data )
			{
			for ( m in data_store$host_data[found$host] )
				{
				item = [$host=found$host, $meta=m];
				add return_data[item];
				}
			}
		}
	else if ( found?$str && found?$str_type )
		{
		# See if the string is known about and it has meta values
		if ( [found$str, found$str_type] in data_store$string_data )
			{
			for ( m in data_store$string_data[found$str, found$str_type] )
				{
				item = [$str=found$str, $str_type=found$str_type, $meta=m];
				add return_data[item];
				}
			}

		# Check if there are any custom str_type lookup functions and add the values to 
		# the result set.
		if ( found$str_type in custom_lookup )
			{
			for ( lookup_func in custom_lookup[found$str_type] )
				{
				# Iterating here because there is no way to merge sets generically.
				for ( custom_lookup_item in lookup_func(found) )
					add return_data[custom_lookup_item];
				}
			}
		}



	# TODO: Later we should probably track whitelist matches.
	# TODO: base this on a set instead of iterating the items.
	for ( item in return_data )
		{
		if ( item$meta$intent == WHITELIST )
			{
			return set();
			}
		}

	return return_data;
	}

function Intel::found_in_conn(c: connection, found: Found)
	{
	if ( find(found) )
		{
		if ( store_metadata )
			{
			local items = lookup(found);
			event Intel::match_in_conn(c, found, items);
			}
		else
			{
			event Intel::match_in_conn_no_items(c, found);
			}
		}
	}

function register_custom_matcher(str_type: SubType, func: function(found: Found): bool)
	{
	if ( str_type !in custom_matchers )
		custom_matchers[str_type] = set(func);
	else
		add custom_matchers[str_type][func];
	}

function register_custom_lookup(str_type: SubType, func: function(found: Found): set[Item])
	{
	if ( str_type !in custom_lookup )
		custom_lookup[str_type] = set(func);
	else
		add custom_lookup[str_type][func];
	}

function unique_data(): count
	{
	return |data_store$host_data| + |data_store$string_data|;
	}

#function get_meta(check: MetaData, metas: set[MetaData]): MetaData
#	{
#	local check_hash = md5_hash(check);
#	for ( m in metas )
#		{
#		if ( check_hash == md5_hash(m) )
#			return m;
#		}
#
#	return [$source=""];
#	}

function has_meta(check: MetaData, metas: set[MetaData]): bool
	{
	local check_hash = md5_hash(check);
	for ( m in metas )
		{
		if ( check_hash == md5_hash(m) )
			return T;
		}

	# The records must not be equivalent if we made it this far.
	return F;
	}

function insert(item: Item)
	{
	local err_msg = "";
	if ( item?$str && ! item?$str_type )
		err_msg = "You must provide a str_type for strings or this item doesn't make sense.";
	
	if ( err_msg == "" )
		{
		# Create and fill out the meta data item.
		local meta = item$meta;
		local metas: set[MetaData];

		if ( item?$host )
			{
			if ( item$host !in data_store$host_data )
				data_store$host_data[item$host] = set();
			
			metas = data_store$host_data[item$host];
			}
		else if ( item?$str )
			{
			if ( [item$str, item$str_type] !in data_store$string_data )
				data_store$string_data[item$str, item$str_type] = set();

			metas = data_store$string_data[item$str, item$str_type];
			}
		else
			{
			err_msg = "Malformed intelligence item";
			}

		for ( m in metas )
			{
			if ( meta$source == m$source )
				{
				if ( has_meta(meta, metas) )
					{
					# It's the same item being inserted again.
					return;
					}
				else
					{
					event Intel::updated_item(item);
					break;
					}
				}
			else
				{
				event Intel::new_item(item);
				break;
				}
			}

		add metas[item$meta];
		return;
		}
	
	if ( err_msg != "" )
		Log::write(Intel::LOG, [$ts=network_time(), $level="warn", $message=err_msg, $item=item]);
	
	return;
	}
	
event insert_event(item: Item)
	{
	insert(item);
	}

