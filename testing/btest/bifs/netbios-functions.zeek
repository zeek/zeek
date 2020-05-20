#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local names_to_decode = set(
		"ejfdebfeebfacacacacacacacacacaaa", # ISATAP
		"fhepfcelehfcepfffacacacacacacabl", # WORKGROUP
		"abacfpfpenfdecfcepfhfdeffpfpacab", # \001\002__MSBROWSE__\002
		"enebfcfeejeocacacacacacacacacaad"); # MARTIN

	for ( name in names_to_decode )
		{
		print decode_netbios_name(name);
		print decode_netbios_name_type(name);
		}
	}
