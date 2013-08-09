#
# @TEST-EXEC: bro -b -s mysig %INPUT

@TEST-START-FILE mysig.sig
signature my_ftp_client {
  ip-proto == tcp
  payload /(|.*[\n\r]) *[uU][sS][eE][rR] /
  tcp-state originator
  event "matched my_ftp_client"
}
@TEST-END-FILE

event bro_init()
	{
	local a = get_matcher_stats();
	if ( a$matchers == 0 )
		exit(1);
	}
