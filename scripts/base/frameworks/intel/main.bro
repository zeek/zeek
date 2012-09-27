##! The intelligence framework provides a way to store and query IP addresses,
##! and strings (with a str_type).  Metadata can
##! also be associated with the intelligence like for making more informated
##! decisions about matching and handling of intelligence.

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
	type StrType: enum {
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
	
	type Item: record {
		host:        addr           &optional;
		net:         subnet         &optional;
		str:         string         &optional;
		str_type:    StrType        &optional;
		
		meta:        MetaData;
	};
	
	## Enum to represent where data came from when it was discovered.
	type Where: enum {
		## A catchall value to represent data of unknown provenance.
		ANYWHERE,
	};

	type Seen: record {
		host:      addr          &optional;
		str:       string        &optional;
		str_type:  StrType       &optional;

		where:     Where;
	};

	type PolicyItem: record {
		pred:   function(seen: Seen, item: Item): bool &optional;

		log_it: bool &default=T;
	};

	## Intelligence data manipulation functions.
	global insert:      function(item: Item);
	global delete_item: function(item: Item): bool;

	## Function to declare discovery of a piece of data in order to check
	## it against known intelligence for matches.
	global seen_in_conn:  function(c: connection, seen: Seen);

	## Intelligence policy variable for handling matches.
	const policy: set[PolicyItem] = {} &redef;

	## API Events that indicate when various things happen internally within the 
	## intelligence framework.
	global new_item: event(item: Item);
	global updated_item: event(item: Item);
}

## Event to represent a match happening in a connection.  On clusters there
## is no assurance as to where this event will be generated so don't 
## assume that arbitrary global state beyond the given data
## will be available.
global match_in_conn: event(c: connection, seen: Seen, items: set[Item]);

# Internal handler for conn oriented matches with no metadata based on the have_full_data setting.
global match_in_conn_no_items: event(c: connection, seen: Seen);

## Optionally store metadata.  This is used internally depending on
## if this is a cluster deployment or not.
const have_full_data = T &redef;

type DataStore: record {
	net_data:    table[subnet] of set[MetaData];
	string_data: table[string, StrType] of set[MetaData];
};
global data_store: DataStore;

function find(seen: Seen): bool
	{
	if ( seen?$host && 
	     seen$host in data_store$net_data )
		{
		return T;
		}
	else if ( seen?$str && seen?$str_type &&
	          [seen$str, seen$str_type] in data_store$string_data )
		{
		return T;
		}
	else
		{
		return F;
		}
	}

function get_items(seen: Seen): set[Item]
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

	if ( seen?$host )
		{
		# See if the host is known about and it has meta values
		if ( seen$host in data_store$net_data )
			{
			for ( m in data_store$net_data[seen$host] )
				{
				# TODO: the lookup should be finding all and not just most specific
				#       and $host/$net should have the correct value.
				item = [$host=seen$host, $meta=m];
				add return_data[item];
				}
			}
		}
	else if ( seen?$str && seen?$str_type )
		{
		# See if the string is known about and it has meta values
		if ( [seen$str, seen$str_type] in data_store$string_data )
			{
			for ( m in data_store$string_data[seen$str, seen$str_type] )
				{
				item = [$str=seen$str, $str_type=seen$str_type, $meta=m];
				add return_data[item];
				}
			}
		}

	return return_data;
	}

function Intel::seen_in_conn(c: connection, seen: Seen)
	{
	if ( find(seen) )
		{
		if ( have_full_data )
			{
			local items = get_items(seen);
			event Intel::match_in_conn(c, seen, items);
			}
		else
			{
			event Intel::match_in_conn_no_items(c, seen);
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
		if ( host !in data_store$net_data )
			data_store$net_data[host] = set();
		
		metas = data_store$net_data[host];
		}
	else if ( item?$net )
		{
		if ( item$net !in data_store$net_data )
			data_store$net_data[item$net] = set();

		metas = data_store$net_data[item$net];
		}
	else if ( item?$str )
		{
		if ( [item$str, item$str_type] !in data_store$string_data )
			data_store$string_data[item$str, item$str_type] = set();

		metas = data_store$string_data[item$str, item$str_type];
		}

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
		}
	}
	