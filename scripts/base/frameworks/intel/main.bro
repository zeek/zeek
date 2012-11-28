##! The intelligence framework provides a way to store and query IP addresses,
##! and strings (with a str_type).  Metadata can
##! also be associated with the intelligence like for making more informed
##! decisions about matching and handling of intelligence.

@load base/frameworks/notice

module Intel;

export {
	redef enum Log::ID += { LOG };
	
	## String data needs to be further categoried since it could represent
	## and number of types of data.
	type StrType: enum {
		## A complete URL without the prefix "http://".
		URL,
		## User-Agent string, typically HTTP or mail message body.
		USER_AGENT,
		## Email address.
		EMAIL,
		## DNS domain name.
		DOMAIN,
		## A user name.
		USER_NAME,
		## File hash which is non-hash type specific.  It's up to the user to query
		## for any relevant hash types.
		FILE_HASH,
		## Certificate SHA-1 hash.
		CERT_HASH,
	};
	
	## Data about an :bro:type:`Intel::Item`
	type MetaData: record {
		## An arbitrary string value representing the data source.  Typically,
		## the convention for this field will be the source name and feed name
		## separated by a hyphen.  For example: "source1-c&c".
		source:      string;
		## A freeform description for the data.
		desc:        string      &optional;
		## A URL for more information about the data.
		url:         string      &optional;
	};
	
	## Represents a piece of intelligence.
	type Item: record {
		## The IP address if the intelligence is about an IP address.
		host:        addr           &optional;
		## The network if the intelligence is about a CIDR block.
		net:         subnet         &optional;
		## The string if the intelligence is about a string.
		str:         string         &optional;
		## The type of data that is in the string if the $str field is set.
		str_type:    StrType        &optional;
		
		## Metadata for the item.  Typically represents more deeply \
		## descriptive data for a piece of intelligence.
		meta:        MetaData;
	};
	
	## Enum to represent where data came from when it was discovered.
	## The convention is to prefix the name with ``IN_``.
	type Where: enum {
		## A catchall value to represent data of unknown provenance.
		IN_ANYWHERE,
	};

	## The $host field and combination of $str and $str_type fields are mutually 
	## exclusive.  These records *must* represent either an IP address being
	## seen or a string being seen.
	type Seen: record {
		## The IP address if the data seen is an IP address.
		host:      addr          &log &optional;
		## The string if the data is about a string.
		str:       string        &log &optional;
		## The type of data that is in the string if the $str field is set.
		str_type:  StrType       &log &optional;

		## Where the data was discovered.
		where:     Where         &log;
		
		## If the data was discovered within a connection, the 
		## connection record should go into get to give context to the data.
		conn:      connection    &optional;
	};

	## Record used for the logging framework representing a positive
	## hit within the intelligence framework.
	type Info: record {
		## Timestamp when the data was discovered.
		ts:       time           &log;

		## If a connection was associated with this intelligence hit,
		## this is the uid for the connection
		uid:      string         &log &optional;
		## If a connection was associated with this intelligence hit,
		## this is the conn_id for the connection.
		id:       conn_id        &log &optional;

		## Where the data was seen.
		seen:     Seen           &log;
		## Sources which supplied data that resulted in this match.
		sources:  set[string]    &log;
	};

	## Intelligence data manipulation functions.
	global insert: function(item: Item);

	## Function to declare discovery of a piece of data in order to check
	## it against known intelligence for matches.
	global seen: function(s: Seen);

	## Event to represent a match in the intelligence data from data that was seen.  
	## On clusters there is no assurance as to where this event will be generated 
	## so do not assume that arbitrary global state beyond the given data
	## will be available.
	##
	## This is the primary mechanism where a user will take actions based on data
	## within the intelligence framework.
	global match: event(s: Seen, items: set[Item]);

	global log_intel: event(rec: Info);
}

# Internal handler for matches with no metadata available.
global match_no_items: event(s: Seen);

# Internal events for cluster data distribution
global new_item: event(item: Item);
global updated_item: event(item: Item);

# Optionally store metadata.  This is used internally depending on
# if this is a cluster deployment or not.
const have_full_data = T &redef;

# The in memory data structure for holding intelligence.
type DataStore: record {
	net_data:    table[subnet] of set[MetaData];
	string_data: table[string, StrType] of set[MetaData];
};
global data_store: DataStore &redef;

# The in memory data structure for holding the barest matchable intelligence.
# This is primarily for workers to do the initial quick matches and store
# a minimal amount of data for the full match to happen on the manager.
type MinDataStore: record {
	net_data:    set[subnet];
	string_data: set[string, StrType];
};
global min_data_store: MinDataStore &redef;


event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_intel]);
	}

function find(s: Seen): bool
	{
	if ( s?$host && 
	     ((have_full_data && s$host in data_store$net_data) || 
	      (s$host in min_data_store$net_data)))
		{
		return T;
		}
	else if ( s?$str && s?$str_type &&
	          ((have_full_data && [s$str, s$str_type] in data_store$string_data) ||
	           ([s$str, s$str_type] in min_data_store$string_data)))
		{
		return T;
		}
	else
		{
		return F;
		}
	}

function get_items(s: Seen): set[Item]
	{
	local item: Item;
	local return_data: set[Item] = set();

	if ( ! have_full_data )
		{
		# A reporter warning should be generated here because this function
		# should never be called from a host that doesn't have the full data.
		# TODO: do a reporter warning.
		return return_data;
		}

	if ( s?$host )
		{
		# See if the host is known about and it has meta values
		if ( s$host in data_store$net_data )
			{
			for ( m in data_store$net_data[s$host] )
				{
				# TODO: the lookup should be finding all and not just most specific
				#       and $host/$net should have the correct value.
				item = [$host=s$host, $meta=m];
				add return_data[item];
				}
			}
		}
	else if ( s?$str && s?$str_type )
		{
		# See if the string is known about and it has meta values
		if ( [s$str, s$str_type] in data_store$string_data )
			{
			for ( m in data_store$string_data[s$str, s$str_type] )
				{
				item = [$str=s$str, $str_type=s$str_type, $meta=m];
				add return_data[item];
				}
			}
		}

	return return_data;
	}

function Intel::seen(s: Seen)
	{
	if ( find(s) )
		{
		if ( have_full_data )
			{
			local items = get_items(s);
			event Intel::match(s, items);
			}
		else
			{
			event Intel::match_no_items(s);
			}
		}
	}


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

event Intel::match(s: Seen, items: set[Item]) &priority=5
	{
	local empty_set: set[string] = set();
	local info: Info = [$ts=network_time(), $seen=s, $sources=empty_set];

	if ( s?$conn )
		{
		info$uid = s$conn$uid;
		info$id  = s$conn$id;
		}

	for ( item in items )
		add info$sources[item$meta$source];

	Log::write(Intel::LOG, info);
	}

function insert(item: Item)
	{
	if ( item?$str && !item?$str_type )
		{
		event reporter_warning(network_time(), fmt("You must provide a str_type for strings or this item doesn't make sense.  Item: %s", item), "");
		return;
		}

	# Create and fill out the meta data item.
	local meta = item$meta;
	local metas: set[MetaData];

	if ( item?$host )
		{
		local host = mask_addr(item$host, is_v4_addr(item$host) ? 32 : 128);
		if ( have_full_data )
			{
			if ( host !in data_store$net_data )
				data_store$net_data[host] = set();

			metas = data_store$net_data[host];
			}

		add min_data_store$net_data[host];
		}
	else if ( item?$net )
		{
		if ( have_full_data )
			{
			if ( item$net !in data_store$net_data )
				data_store$net_data[item$net] = set();

			metas = data_store$net_data[item$net];
			}

		add min_data_store$net_data[item$net];
		}
	else if ( item?$str )
		{
		if ( have_full_data )
			{
			if ( [item$str, item$str_type] !in data_store$string_data )
				data_store$string_data[item$str, item$str_type] = set();

			metas = data_store$string_data[item$str, item$str_type];
			}

		add min_data_store$string_data[item$str, item$str_type];
		}

	local updated = F;
	if ( have_full_data )
		{
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
					# Same source, different metadata means updated item.
					updated = T;
					}
				}
			}
		add metas[item$meta];
		}
	
	if ( updated )
		event Intel::updated_item(item);
	else
		event Intel::new_item(item);
	}
	
