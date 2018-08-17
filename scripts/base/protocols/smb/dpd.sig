signature dpd_smb {
	ip-proto == tcp
	payload /^....[\xfe\xff]SMB/
	enable "smb"
}