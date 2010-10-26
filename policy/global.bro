@load site
@load signatures

const private_address_space: set[subnet] = {10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8, 172.16.0.0/12};

# These go along with the functions in functions-ext.bro for mapping IP
# addresses to email contact information for IP addresses and subnets.
const one_to_32: vector of count = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
const subnet_to_admin_table: table[subnet] of string = {
	[0.0.0.0/0] = "",
} &redef;

###############################################################
# Make the default signature action ignore certain signatures
###############################################################
const ignored_signatures = /INTENTIONALLY_BLANK/ &redef;
function default_signature_action(sig: string): SigAction
	{
	if ( ignored_signatures in sig )
		return SIG_IGNORE;
	else
		return SIG_ALARM;
	}
redef signature_actions &default=default_signature_action;
###############################################################

# This defines the event that is used by the bro-dblogger application
# to push data from Bro directly into a database.
#  see: http://github.com/sethhall/bro-dblogger
global db_log: event(db_table: string, data: any);

@load functions-ext
@load logging-ext
