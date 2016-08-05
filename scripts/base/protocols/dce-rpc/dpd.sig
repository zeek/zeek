
signature dpd_dce_rpc {
	ip-proto == tcp
	payload /^\x05[\x00\x01][\x00-\x13]\x03/
	enable "DCE_RPC"
}