
refine connection GSSAPI_Conn += {
	%member{
		analyzer::Analyzer *ntlm;
		analyzer::Analyzer *krb5;
	%}

	%init{
		ntlm=0;
		krb5=0;
	%}

	%cleanup{
		if ( ntlm )
			{
			ntlm->Done();
			delete ntlm;
			ntlm=0;
			}

		if ( krb5 )
			{
			krb5->Done();
			delete krb5;
			krb5=0;
			}
	%}

	function forward_blob(val: GSSAPI_NEG_TOKEN_MECH_TOKEN, is_orig: bool): bool
		%{
        if ( ${val.token}.length() >= 7 &&
             memcmp("NTLMSSP", ${val.token}.begin(), 7) == 0 )
            {
            // ntlmssp
            if ( ! ntlm )
                ntlm = analyzer_mgr->InstantiateAnalyzer("NTLM", bro_analyzer()->Conn());

            if ( ntlm )
                ntlm->DeliverStream(${val.token}.length(),
                                    ${val.token}.begin(), is_orig);
            }


        else if ( 0x60 == *(${val.token}.begin()) )
            {
            // probably KRB

            const unsigned char *p = ${val.token}.begin();
            int len_to_send = ${val.token}.length();
            p++;
            len_to_send--;

            int shift = 1;
            if ( ((*p) & 0x80) > 0 )
                {
                    shift += (*p) & 0x7f;
                }

            p += shift;  // eating an ASN.1 meta
            len_to_send -= shift;

            // should now be pointing at OID
            if ( (*p) == 0x06 )
                {
                    p++;
                    len_to_send--;
                    len_to_send -= (*p) + 1;
                    p += (*p) + 1;  // eating the OID.  assuming short form on
                                    // OID len

                    // should now be pointing at the type of KRB
                    // 0x0100 or 0x0200
                    // krb5 && ms-krb5
                    if ( ! krb5 )
                        krb5 = analyzer_mgr->InstantiateAnalyzer("KRB", bro_analyzer()->Conn());

                    if ( krb5 ) // accepting all KRB types (REQ, REP, etc)
                          
                        {
                        krb5->DeliverPacket(len_to_send-2,
                                            p+2, 
                                            is_orig, 0, 0, 0);
                        }
                }
            } 
		return true;
		%}

	function proc_gssapi_neg_result(val: GSSAPI_NEG_TOKEN_RESP_Arg): bool
		%{
		if ( gssapi_neg_result )
			{
			BifEvent::generate_gssapi_neg_result(bro_analyzer(),
			                                     bro_analyzer()->Conn(),
			                                     binary_to_int64(${val.neg_state.encoding.content}));
			}

		return true;
		%}
}

refine typeattr GSSAPI_NEG_TOKEN_MECH_TOKEN += &let {
	fwd: bool = $context.connection.forward_blob(this, is_orig);
};

refine typeattr GSSAPI_NEG_TOKEN_RESP_Arg += &let {
	proc: bool = $context.connection.proc_gssapi_neg_result(this) &if(seq_meta.index==0);
};

