# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff software.log
# @TEST-EXEC: btest-diff notice.log

@load base/frameworks/software
@load policy/frameworks/software/version-changes

const fake_software_name = "my_fake_software";
redef Software::asset_tracking = ALL_HOSTS;
redef Software::interesting_version_changes += {fake_software_name};

global versions: vector of string = vector("1.0.0", "1.1.0", "1.2.0", "1.0.0");
global version_index = 0;
global c = 0;

event new_software()
	{
	local v = versions[version_index];
	local cid = conn_id($orig_h = 127.0.0.1, $orig_p = 22/tcp,
						$resp_h = 127.0.0.1, $resp_p = 22/tcp);
	local si = Software::Info($name=fake_software_name,
							  $unparsed_version=fmt("%s %s",
							  						fake_software_name, v),
							  $host=127.0.0.1);
	Software::found(cid, si);

	++version_index;
	++c;

	if ( version_index >= |versions| )
		version_index = 0;

	if ( c < 10 )
		event new_software();
	}

event zeek_init()
	{
	event new_software();
	}
