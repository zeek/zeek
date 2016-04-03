
refine connection SMB_Conn += {

	function forward_gssapi(data: bytestring, is_orig: bool): bool
		%{
		if ( gssapi )
			gssapi->DeliverStream(${data}.length(), ${data}.begin(), is_orig);

		return true;
		%}
};
