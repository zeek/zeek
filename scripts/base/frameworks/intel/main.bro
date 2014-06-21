##! The intelligence framework provides a way to store and query IP addresses,
##! and strings (with a str_type).  Metadata can
##! also be associated with the intelligence, like for making more informed
##! decisions about matching and handling of intelligence.

@load base/frameworks/notice

module Intel;

export {
	redef enum Log::ID += { LOG };
	
	## Enum type to represent various types of intelligence data.
	type Type: enum {
		## An IP address.
		ADDR,
		## A complete URL without the prefix ``"http://"``.
		URL,
		## Software name.
		SOFTWARE,
		## Email address.
		EMAIL,
		## DNS domain name.
		DOMAIN,
		## A user name.
		USER_NAME,
		## File hash which is non-hash type specific.  It's up to the
		## user to query for any relevant hash types.
		FILE_HASH,
		## File name.  Typically with protocols with definite
		## indications of a file name.
		FILE_NAME,
		## Certificate SHA-1 hash.
		CERT_HASH,
	};
	
	## Data about an :bro:type:`Intel::Item`.
	type MetaData: record {
		## An arbitrary string value representing the data source.
		## Typically, the convention for this field will be the source
		## name and feed name separated by a hyphen.
		## For example: "source1-c&c".
		source:      string;
		## A freeform description for the data.
		desc:        string      &optional;
		## A URL for more information about the data.
		url:         string      &optional;
	};
	
	## Represents a piece of intelligence.
	type Item: record {
		## The intelligence indicator.
		indicator:      string;

		## The type of data that the indicator field represents.
		indicator_type: Type;
		
		## Metadata for the item.  Typically represents more deeply
		## descriptive data for a piece of intelligence.
		meta:           MetaData;
	};
	
	## Enum to represent where data came from when it was discovered.
	## The convention is to prefix the name with ``IN_``.
	type Where: enum {
		## A catchall value to represent data of unknown provenance.
		IN_ANYWHERE,
	};

	type Seen: record {
		## The string if the data is about a string.
		indicator:       string        &log &optional;

		## The type of data that the indicator represents.
		indicator_type:  Type          &log &optional;

		## If the indicator type was :bro:enum:`Intel::ADDR`, then this 
		## field will be present.
		host:            addr          &optional;

		## Where the data was discovered.
		where:           Where         &log;
		
		## If the data was discovered within a connection, the 
		## connection record should go here to give context to the data.
		conn:            connection    &optional;

		## If the data was discovered within a file, the file record
		## should go here to provide context to the data.
		f:               fa_file       &optional;
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

		## If a file was associated with this intelligence hit,
		## this is the uid for the file.
		fuid:           string   &log &optional;
		## A mime type if the intelligence hit is related to a file.  
		## If the $f field is provided this will be automatically filled
		## out.
		file_mime_type: string   &log &optional;
		## Frequently files can be "described" to give a bit more context.
		## If the $f field is provided this field will be automatically
		## filled out.
		file_desc:      string   &log &optional;

		## Where the data was seen.
		seen:     Seen           &log;
		## Sources which supplied data that resulted in this match.
		sources:  set[string]    &log &default=string_set();
	};

	## Intelligence data manipulation functions.
	global insert: function(item: Item);

	## Function to declare discovery of a piece of data in order to check
	## it against known intelligence for matches.
	global seen: function(s: Seen);

	## Event to represent a match in the intelligence data from data that
	## was seen.  On clusters there is no assurance as to where this event
	## will be generated so do not assume that arbitrary global state beyond
	## the given data will be available.
	##
	## This is the primary mechanism where a user will take actions based on
	## data within the intelligence framework.
	global match: event(s: Seen, items: set[Item]);

	global log_intel: event(rec: Info);
}

# Internal handler for matches with no metadata available.
global match_no_items: event(s: Seen);

# Internal events for cluster data distribution.
global new_item: event(item: Item);
global updated_item: event(item: Item);

# Optionally store metadata.  This is used internally depending on
# if this is a cluster deployment or not.
const have_full_data = T &redef;

# The in memory data structure for holding intelligence.
type DataStore: record {
	host_data:    table[addr] of set[MetaData];
	string_data:  table[string, Type] of set[MetaData];
};
global data_store: DataStore &redef;

# The in memory data structure for holding the barest matchable intelligence.
# This is primarily for workers to do the initial quick matches and store
# a minimal amount of data for the full match to happen on the manager.
type MinDataStore: record {
	host_data:    set[addr];
	string_data:  set[string, Type];
};
global min_data_store: MinDataStore &redef;


event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_intel]);
	}

function find(s: Seen): bool
	{
	if ( s?$host )
		{
		return ((s$host in min_data_store$host_data) || 
		        (have_full_data && s$host in data_store$host_data));
		}
	else if ( ([to_lower(s$indicator), s$indicator_type] in min_data_store$string_data) ||
	           (have_full_data && [to_lower(s$indicator), s$indicator_type] in data_store$string_data) )
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
	local return_data: set[Item];

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
		if ( s$host in data_store$host_data )
			{
			for ( m in data_store$host_data[s$host] )
				{
				add return_data[Item($indicator=cat(s$host), $indicator_type=ADDR, $meta=m)];
				}
			}
		}
	else
		{
		local lower_indicator = to_lower(s$indicator);
		# See if the string is known about and it has meta values
		if ( [lower_indicator, s$indicator_type] in data_store$string_data )
			{
			for ( m in data_store$string_data[lower_indicator, s$indicator_type] )
				{
				add return_data[Item($indicator=s$indicator, $indicator_type=s$indicator_type, $meta=m)];
				}
			}
		}

	return return_data;
	}

function Intel::seen(s: Seen)
	{
	if ( find(s) )
		{
		if ( s?$host )
			{
			s$indicator = cat(s$host);
			s$indicator_type = Intel::ADDR;
			}

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
	local info = Info($ts=network_time(), $seen=s);

	if ( s?$f )
		{
		if ( s$f?$conns && |s$f$conns| == 1 )
			{
			for ( cid in s$f$conns )
				s$conn = s$f$conns[cid];
			}

		if ( ! info?$fuid )
			info$fuid = s$f$id;

		if ( ! info?$file_mime_type && s$f?$mime_type )
			info$file_mime_type = s$f$mime_type;

		if ( ! info?$file_desc )
			info$file_desc = Files::describe(s$f);
		}

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
	# Create and fill out the meta data item.
	local meta = item$meta;
	local metas: set[MetaData];

	# All intelligence is case insensitive at the moment.
	local lower_indicator = to_lower(item$indicator);

	if ( item$indicator_type == ADDR )
		{
		local host = to_addr(item$indicator);
		if ( have_full_data )
			{
			if ( host !in data_store$host_data )
				data_store$host_data[host] = set();

			metas = data_store$host_data[host];
			}

		add min_data_store$host_data[host];
		}
	else
		{
		if ( have_full_data )
			{
			if ( [lower_indicator, item$indicator_type] !in data_store$string_data )
				data_store$string_data[lower_indicator, item$indicator_type] = set();

			metas = data_store$string_data[lower_indicator, item$indicator_type];
			}

		add min_data_store$string_data[lower_indicator, item$indicator_type];
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
	
