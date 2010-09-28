# $Id: filter-duplicates.bro 6868 2009-08-17 04:18:02Z robin $
#
# Script to filter out duplicate alarms reported by multiple backends. 

module FilterDuplicates;

@load notice

export {
	const log_duplicates = T &redef;

	# Returns false if this notice is a duplicate of another notice 
	# we have seen before; if log_duplicates is true, it also logs
	# it into "notice.duplicates.log". Return true if we have not 
	# seen it before.
	global is_new: function(n: notice_info) : bool;

	# Per default, a Notice is assumed to be unique. The following table
	# defines functions finding duplicates on a per-notice bases. These 
	# functions will be called with two instances of their notice type, and 
	# must return T if they consider the two to be equal.
	global filters: table[Notice] of function(n: notice_info): string &redef;

	# Some predefined functions that can be used with the filters table.
    
		# Filters by matching source addresses.    
	global match_src: function(n: notice_info) : string;
		# Filters by matching source addresses and the number attributes.
	global match_src_num: function(n: notice_info) : string;
		# Filters by matching source addresses and the port attributes.
	global match_src_port: function(n: notice_info) : string;
}

function match_src(n: notice_info) : string
	{
	local src = n?$src ? fmt("%s", n$src) : "";
	return fmt("%s#%s", n$note, src);
	}

function match_src_num(n: notice_info) : string
	{
	local src = n?$src ? fmt("%s", n$src) : "";
	local num = n?$src ? fmt("%d", n$n) : "";
	return fmt("%s#%s#%s", n$note, src, num);
	}

function match_src_port(n: notice_info) : string
	{
	local src = n?$src ? fmt("%s", n$src) : "";
	local p = n?$p ? fmt("%d", n$p) : "";
	return fmt("%s#%s#%s", n$note, src, p);
	}

global dupl_log: file;

event bro_init()
	{
	if ( log_duplicates )
		dupl_log = open_log_file( "notice-duplicates" );
	}

global notices: set[string] &read_expire = 2mins;

function is_new(n: notice_info) : bool
	{
	local idx = n$note;
	
	if ( idx !in filters )
		# No filtering for this notice type.
		return T;
	
	local key = filters[idx](n);
	
	if ( key in notices ) 
		{
		# A duplicate.
		if ( log_duplicates )
			print dupl_log, build_notice_info_string_tagged(n);
	
		return F;
		}

	# New one.
	add notices[key];
	return T;
	}
