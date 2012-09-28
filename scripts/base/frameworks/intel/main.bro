##! The intelligence framework provides a way to store and query IP addresses,
##! and strings (with a str_type).  Metadata can
##! also be associated with the intelligence like for making more informated
##! decisions about matching and handling of intelligence.

@load base/frameworks/notice

module Intel;

export {
	redef enum Log::ID += { LOG };
	
	redef enum Notice::Type += {
		## Notice type to indicate an intelligence hit.
		Detection,
	};
	
	## String data needs to be further categoried since it could represent
	## and number of types of data.
	type StrType: enum {
		## A complete URL without the prefix "http://".
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
		IN_ANYWHERE,
	};

	type Seen: record {
		host:      addr          &optional &log;
		str:       string        &optional &log;
		str_type:  StrType       &optional &log;

		where:     Where         &log;
		
		conn:      connection    &optional;
	};

	type Info: record {
		ts:   time    &log;

		uid:  string  &log &optional;
		id:   conn_id &log &optional;

		seen: Seen    &log;
	};

	type PolicyItem: record {
		pred:   function(s: Seen, item: Item): bool &optional;

		log_it: bool &default=T;
	};

	## Intelligence data manipulation functions.
	global insert: function(item: Item);

	## Function to declare discovery of a piece of data in order to check
	## it against known intelligence for matches.
	global seen: function(s: Seen);

	## Intelligence policy variable for handling matches.
	const policy: set[PolicyItem] = {
	#	[$pred(s: Seen) = { return T; },
	#	 $action=Intel::ACTION_LOG]
	} &redef;

	## API Events that indicate when various things happen internally within the 
	## intelligence framework.
	global new_item: event(item: Item);
	global updated_item: event(item: Item);

	global log_intel: event(rec: Info);
}

# Event to represent a match happening in a connection.  On clusters there
# is no assurance as to where this event will be generated so don't 
# assume that arbitrary global state beyond the given data
# will be available.
global match: event(s: Seen, items: set[Item]);

# Internal handler for conn oriented matches with no metadata based on the have_full_data setting.
global match_no_items: event(s: Seen);

# Optionally store metadata.  This is used internally depending on
# if this is a cluster deployment or not.
const have_full_data = T &redef;

# The in memory data structure for holding intelligence.
type DataStore: record {
	net_data:    table[subnet] of set[MetaData];
	string_data: table[string, StrType] of set[MetaData];
};
global data_store: DataStore;

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_intel]);
	}

function find(s: Seen): bool
	{
	if ( s?$host && 
	     s$host in data_store$net_data )
		{
		return T;
		}
	else if ( s?$str && s?$str_type &&
	          [s$str, s$str_type] in data_store$string_data )
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

#global total_seen=0;
#event bro_done()
#	{
#	print fmt("total seen: %d", total_seen);
#	}

function Intel::seen(s: Seen)
	{
	#++total_seen;
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

event Intel::match(s: Seen, items: set[Item])
	{
	local info: Info = [$ts=network_time(), $seen=s];

	if ( s?$conn )
		{
		info$uid = s$conn$uid;
		info$id  = s$conn$id;
		}

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
	