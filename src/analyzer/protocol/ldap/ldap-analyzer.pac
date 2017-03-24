%extern{
#include <cstdlib>
#include <vector>
#include <string>
#include "net_util.h"
#include "util.h"
%}

%header{
RecordVal * build_modreq_pdu(const ModifyReqPDU *pdu);
RecordVal * build_modDNreq_pdu(const ModifyDNReqPDU *pdu);
RecordVal * build_addreq_pdu(const AddReqPDU *pdu);
RecordVal * build_delreq_pdu(const DeleteReqPDU *pdu);
RecordVal * build_ldap_res(LDAPResult *pdu);
%}

%code{

/*
Builds a ModifyRequest record
- messageID
- object/entry to be modified
- string of modifications to be performed
*/

RecordVal * build_modreq_pdu(const ModifyReqPDU *pdu)  
    {
    RecordVal *rv = new RecordVal(BifType::Record::LDAP::ModifyReqPDU);

	rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
	rv->Assign(1, asn1_octet_string_to_val(pdu->object()));
	
	vector<ModificationControl*>  mods = *pdu->mods();
        std::string fullStr;
	for (auto it = mods.begin(); it != mods.end(); ++it){
                if( (*it)->mod_or_control_case_index() != 10 ) continue;

                switch( (*it)->mod()->op())  {
                  case 0:
                    fullStr.append("add ");
                    break;
                  case 1:
                    fullStr.append("delete ");
                    break;
                  case 2:
                    fullStr.append("replace ");
                    break;
                  default:
                    fullStr.append("unknown ");
                    break;
                };

                const u_char * typeStr = asn1_octet_string_to_val((*it)->mod()->type())->Bytes();
                fullStr.append((const char*)typeStr);
                fullStr.append(" ");

                const u_char * valStr = asn1_octet_string_to_val((*it)->mod()->val())->Bytes();
                fullStr.append((const char*)valStr);
                fullStr.append("/");
	}

        rv->Assign(2, new StringVal(fullStr));

    return rv;
    }


/*
Builds an AddRequest record
- messageID
- object/entry to be added
- string of attributes to be added
*/

RecordVal * build_addreq_pdu(const AddReqPDU *pdu)
	{
	RecordVal *rv = new RecordVal(BifType::Record::LDAP::AddReqPDU);
	rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
	rv->Assign(1, asn1_octet_string_to_val(pdu->entry()));

	vector<Attribute*>  atts = *pdu->attributes()->atts();
        std::string fullStr;
	for (auto it = atts.begin(); it != atts.end(); ++it){
                if( (*it)->control_check_case_index() != 48 ) continue;


                const u_char * typeStr = asn1_octet_string_to_val((*it)->att()->type())->Bytes();
                fullStr.append((const char*)typeStr);
                fullStr.append(" ");

                const u_char * valStr = asn1_octet_string_to_val((*it)->att()->val())->Bytes();
                fullStr.append((const char*)valStr);
                fullStr.append("/");
	}

        rv->Assign(2, new StringVal(fullStr));

    return rv;
	}


/*
Builds a ModifyDNRequest record
- messageID
- object/entry to be modified
- string of newRDN, newSuperior, and whether or not to delete the old RDN
*/

RecordVal * build_modDNreq_pdu(const ModifyDNReqPDU *pdu)
	{
	RecordVal *rv = new RecordVal(BifType::Record::LDAP::ModifyDNReqPDU);
	rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
	rv->Assign(1, asn1_octet_string_to_val(pdu->entry()));

	std::string fullStr;
	const u_char * newRDN = asn1_octet_string_to_val(pdu->newrdn())->Bytes();
	const u_char * newSupe = bytestring_to_val(pdu->newSuperior())->Bytes();

	fullStr.append("newRDN: ");
	fullStr.append((const char*)newRDN);
	fullStr.append(" ");
	fullStr.append("newSuperior: ");
	fullStr.append((const char*)newSupe);
	fullStr.append(" ");
	fullStr.append("deleteold: ");

	uint8 deleteold = pdu->deleteoldrdn();
	             switch(deleteold)  {
                  case 0:
                    fullStr.append("false ");
                    break;
                  default:
                    fullStr.append("true ");
                    break;
                };
	rv->Assign(2, new StringVal(fullStr));
	return rv;
	}

/*
Builds a DeleteRequest record
- messageID
- object/entry to be deleted
*/

RecordVal * build_delreq_pdu(const DeleteReqPDU *pdu)
	{
	RecordVal *rv = new RecordVal(BifType::Record::LDAP::DeleteReqPDU);
	rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
	rv->Assign(1, bytestring_to_val(pdu->request()));

	return rv;
	}
/*
Builds a, LDAPResult record
- messageID
- result of request
- error string 
*/

RecordVal * build_ldap_res(LDAPResult *pdu)
    {
    RecordVal *rv = new RecordVal(BifType::Record::LDAP::LDAPResultPDU);
    rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
    rv->Assign(1, new Val(pdu->result(), TYPE_INT));
    rv->Assign(2, asn1_octet_string_to_val(pdu->error()));

    return rv;
    }


%}

refine connection LDAP_Conn += {

#
#Connection oriented functions:
#
	%member{
		// Fields used to determine if the protocol has been confirmed or not.
		bool confirmed;
		bool orig_pdu;
		bool resp_pdu;
		%}

	%init{
		confirmed = false;
		orig_pdu = false;
		resp_pdu = false;
		%}

	function SetPDU(is_orig: bool): bool
		%{
		if ( is_orig )
			orig_pdu = true;
		else
			resp_pdu = true;

		return true;
		%}

	function SetConfirmed(): bool
		%{
		confirmed = true;
		return true;
		%}

	function IsConfirmed(): bool
		%{
		return confirmed && orig_pdu && resp_pdu;
		%}

#
#Handle ModifyRequest
#

	function proc_ldap_mod_req(pdu: ModifyReqPDU): bool
	    %{
	    if ( ! ldap_mod_req )
	        return false;
		
	    BifEvent::generate_ldap_mod_req(bro_analyzer(),
	                bro_analyzer()->Conn(),
					build_modreq_pdu(${pdu}));
					
		return true;                       
	    %}

#
#Handle ModifyResponse
#

	function proc_ldap_mod_res(pdu: ModifyResPDU): bool
	    %{
	    if ( ! ldap_mod_res )
	        return false;

	    BifEvent::generate_ldap_mod_res(bro_analyzer(),
	                bro_analyzer()->Conn(),
                        build_ldap_res(pdu->result()));

		return true;                       
	    %}

#
#Handle DeleteRequest
#
	    
	function proc_ldap_del_req(pdu: DeleteReqPDU): bool
	    %{
	    if ( ! ldap_del_req )
	        return false;
		
	    BifEvent::generate_ldap_del_req(bro_analyzer(),
	                bro_analyzer()->Conn(),	
					build_delreq_pdu(pdu));

		return true;                       
	    %}

#
#Handle DeleteResponse
#
	    
	function proc_ldap_del_res(pdu: DeleteResPDU): bool
	    %{
	    if ( ! ldap_del_res )
	        return false;

	    BifEvent::generate_ldap_mod_res(bro_analyzer(),
	                bro_analyzer()->Conn(),
                        build_ldap_res(pdu->result()));

		return true;                       
	    %}
	    
#
#Handle AddRequest
#

	function proc_ldap_add_req(pdu: AddReqPDU): bool
	    %{
	    if ( ! ldap_add_req )
	        return false;
		
	    BifEvent::generate_ldap_add_req(bro_analyzer(),
	                bro_analyzer()->Conn(),
					build_addreq_pdu(pdu));
		return true;                       
	    %}
	
#
#Handle AddResponse
#
    
	function proc_ldap_add_res(pdu: AddResPDU): bool
	    %{
	    if ( ! ldap_add_res )
	        return false;

	    BifEvent::generate_ldap_add_res(bro_analyzer(),
	                bro_analyzer()->Conn(),
                        build_ldap_res(pdu->result()));
				
	    return true;
	    %}

#
#Handle ModifyDNRequest
#

	function proc_ldap_modDN_req(pdu: ModifyDNReqPDU): bool
	    %{
	    if ( ! ldap_modDN_req )
	        return false;
		
	    BifEvent::generate_ldap_modDN_req(bro_analyzer(),
	                bro_analyzer()->Conn(),
					build_modDNreq_pdu(pdu));
		return true;                       
	    %}

#
#Handle ModifyDNResponse
#

	function proc_ldap_modDN_res(pdu: ModifyDNResPDU): bool
	    %{
	    if ( ! ldap_modDN_res )
	        return false;

	    BifEvent::generate_ldap_modDN_res(bro_analyzer(),
	                bro_analyzer()->Conn(),
                    build_ldap_res(pdu->result()));

		return true;                       
	    %}

#
#ASN Check functions
#

	function check_int(rec: ASN1Integer): bool
		%{
		return check_tag(rec->encoding()->meta(), ASN1_INTEGER_TAG) &&
		       check_int_width(rec);
		%}

	function check_int_width(rec: ASN1Integer): bool
		%{
		int len = rec->encoding()->content().length();

		if ( len <= 9 )
			// All integers use two's complement form, so an unsigned 64-bit
			// integer value can require 9 octets to encode if the highest
			// order bit is set.
			return true;

		throw binpac::Exception(fmt("ASN.1 integer width overflow: %d", len));
		return false;
		%}

	function check_tag(rec: ASN1EncodingMeta, expect: uint8): bool
		%{
		if ( rec->tag() == expect )
			return true;

		// Unwind now to stop parsing because it's definitely the
		// wrong protocol and parsing further could be expensive.
		// Upper layer of analyzer will catch and call ProtocolViolation().
		throw binpac::Exception(fmt("Got ASN.1 tag %d, expect %d",
		                        rec->tag(), expect));
		return false;
		%}

};



refine typeattr ModifyReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_mod_req(this);

};

refine typeattr ModifyResPDU += &let {
	proc: bool = $context.connection.proc_ldap_mod_res(this);

};


refine typeattr DeleteReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_del_req(this);

};

refine typeattr DeleteResPDU += &let {
	proc: bool = $context.connection.proc_ldap_del_res(this);

};

refine typeattr AddReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_add_req(this);

};

refine typeattr AddResPDU += &let {
	proc: bool = $context.connection.proc_ldap_add_res(this);

};

refine typeattr ModifyDNReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_modDN_req(this);

};

refine typeattr ModifyDNResPDU += &let {
	proc: bool = $context.connection.proc_ldap_modDN_res(this);


};


refine typeattr ASN1SequenceMeta += &let {
	valid: bool = $context.connection.check_tag(encoding, ASN1_SEQUENCE_TAG);
                                           
};

refine typeattr ASN1Integer += &let {
	valid: bool = $context.connection.check_int(this);

};

refine typeattr ASN1OctetString += &let {
	valid: bool = $context.connection.check_tag(encoding.meta, ASN1_OCTET_STRING_TAG);

};

refine typeattr ASN1ObjectIdentifier += &let {
	valid: bool = $context.connection.check_tag(encoding.meta, ASN1_OBJECT_IDENTIFIER_TAG);

};
