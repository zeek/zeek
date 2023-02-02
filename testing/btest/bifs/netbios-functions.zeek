#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function decode_name(name: string)
	{
	local dn = decode_netbios_name(name);
	local suffix = decode_netbios_name_type(name);
	print suffix, |dn|, dn;
	}

local encoded_names = vector(
		"ejfdebfeebfacacacacacacacacacaaa", # ISATAP
		"fhepfcelehfcepfffacacacacacacabl", # WORKGROUP
		"abacfpfpenfdecfcepfhfdeffpfpacab", # \001\002__MSBROWSE__\002
		"enebfcfeejeocacacacacacacacacaad", # MARTIN
		"FEEIEFCAEOEFFEECEJEPFDCAEOEBENEF", # THE NETBIOS NAM
		"cbcccdcecfcgchcicjckclcmcncodnaa", # !"#$%&'()*+,-.=
		"dkdleafofphlhnhoaaaaaaaaaaaaaaaa", # :;@^_{}~
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", # empty
		"cacacacacacacacacacacacacacacaca", # empty
		"abcd",                             # invalid length
		"~jfdebfeebfacacacacacacacacacaaa", # invalid alphabet
		"0jfdebfeebfacacacacacacacacacaaa", # invalid alphabet
		"lpejldmeebfacacacacacacacacacaaa", # non-ascii stuff
);

for ( i in encoded_names )
	decode_name(encoded_names[i]);
