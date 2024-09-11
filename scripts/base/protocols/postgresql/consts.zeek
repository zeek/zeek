module PostgreSQL;

export {
	# https://www.postgresql.org/docs/current/protocol-error-fields.html
	global error_ids: table[string] of string = {
		["S"] = "SeverityLocalized",
		["V"] = "Severity",  # non-localized
		["C"] = "Code",
		["M"] = "Message",
		["D"] = "Detail",
		["H"] = "Hint",
		["P"] = "Position",
		["p"] = "InternalPosition",
		["q"] = "InternalQuery",
		["W"] = "Where",
		["s"] = "Schema",
		["t"] = "Table",
		["c"] = "Column",
		["d"] = "Data",
		["n"] = "Constraint",
		["F"] = "File",
		["L"] = "Line",
		["R"] = "Routine",
	} &default=function(c: string): string { return fmt("UnknownErrorId%s", c); } &redef;

	global auth_ids: table[count] of string = {
		[2] = "KerberosV5",
		[3] = "CleartextPassword",
		[5] = "MD5Password",
		[7] = "GSSAPI",
		[8] = "GSSAPIContinue",
		[9] = "SSPI",
		[10] = "SASL",
		[11] = "SASLContinue",
		[12] = "SASLFinal",
	} &default=function(id: count): string { return fmt("UnknownAuthId%s", id); } &redef;
}
