# Kerberos pre-authentication data is a significant piece of the complexity,
# so we're splitting this off

%extern{
#include "file_analysis/Manager.h"
#include "Desc.h"
%}

%header{
VectorVal* proc_padata(const KRB_PA_Data_Sequence* data, const BroAnalyzer bro_analyzer, bool is_error);
%}

%code{
VectorVal* proc_padata(const KRB_PA_Data_Sequence* data, const BroAnalyzer bro_analyzer, bool is_error)
{
	auto vv = make_intrusive<VectorVal>(zeek::id::lookup_type<VectorType>("KRB::Type_Value_Vector"));

	if ( ! data->data()->has_padata() )
		return vv.release();

	for ( uint i = 0; i < data->data()->padata_elems()->size(); ++i)
		{
		KRB_PA_Data* element = (*data->data()->padata_elems())[i];
		int64 data_type = element->data_type();

		if ( is_error && ( data_type == PA_PW_AS_REQ || data_type == PA_PW_AS_REP ) )
			data_type = 0;

		switch( data_type )
			{
			case PA_TGS_REQ:
				// will be generated as separate event
				break;
			case PA_ENC_TIMESTAMP:
				// encrypted timestamp is unreadable
				break;
			case PA_PW_SALT:
				{
				RecordVal * type_val = new RecordVal(BifType::Record::KRB::Type_Value);
				type_val->Assign(0, val_mgr->Count(element->data_type()));
				type_val->Assign(1, to_stringval(element->pa_data_element()->pa_pw_salt()->encoding()->content()));
				vv->Assign(vv->Size(), type_val);
				break;
				}
			case PA_ENCTYPE_INFO:
				{
				RecordVal * type_val = new RecordVal(BifType::Record::KRB::Type_Value);
				type_val->Assign(0, val_mgr->Count(element->data_type()));
				type_val->Assign(1, to_stringval(element->pa_data_element()->pf_enctype_info()->salt()));
				vv->Assign(vv->Size(), type_val);
				break;
				}
			case PA_ENCTYPE_INFO2:
				{
				RecordVal * type_val = new RecordVal(BifType::Record::KRB::Type_Value);
				type_val->Assign(0, val_mgr->Count(element->data_type()));
				type_val->Assign(1, to_stringval(element->pa_data_element()->pf_enctype_info2()->salt()));
				vv->Assign(vv->Size(), type_val);
				break;
				}
			case PA_PW_AS_REQ:
				{
				const bytestring& cert = element->pa_data_element()->pa_pk_as_req()->cert();

				ODesc common;
				common.AddRaw("Analyzer::ANALYZER_KRB");
				common.Add(bro_analyzer->Conn()->StartTime());
				// Request means is_orig=T
				common.AddRaw("T", 1);
				bro_analyzer->Conn()->IDString(&common);

				ODesc file_handle;
				file_handle.Add(common.Description());
				file_handle.Add(0);

				string file_id = file_mgr->HashHandle(file_handle.Description());

				file_mgr->DataIn(reinterpret_cast<const u_char*>(cert.data()),
				                 cert.length(), bro_analyzer->GetAnalyzerTag(),
				                 bro_analyzer->Conn(), true, file_id, "application/x-x509-user-cert");
				file_mgr->EndOfFile(file_id);

				break;
				}
			case PA_PW_AS_REP:
				{
				const bytestring& cert = element->pa_data_element()->pa_pk_as_rep()->cert();

				ODesc common;
				common.AddRaw("Analyzer::ANALYZER_KRB");
				common.Add(bro_analyzer->Conn()->StartTime());
				// Response means is_orig=F
				common.AddRaw("F", 1);
				bro_analyzer->Conn()->IDString(&common);

				ODesc file_handle;
				file_handle.Add(common.Description());
				file_handle.Add(1);

				string file_id = file_mgr->HashHandle(file_handle.Description());

				file_mgr->DataIn(reinterpret_cast<const u_char*>(cert.data()),
				                 cert.length(), bro_analyzer->GetAnalyzerTag(),
				                 bro_analyzer->Conn(), false, file_id, "application/x-x509-user-cert");
				file_mgr->EndOfFile(file_id);

				break;
				}
			default:
				{
				if ( ! is_error && element->pa_data_element()->unknown()->meta()->length() > 0 )
					{
					RecordVal * type_val = new RecordVal(BifType::Record::KRB::Type_Value);
					type_val->Assign(0, val_mgr->Count(element->data_type()));
					type_val->Assign(1, to_stringval(element->pa_data_element()->unknown()->content()));
					vv->Assign(vv->Size(), type_val);
					}
				break;
				}
			}
		}
	return vv.release();
}
%}

# Basic structure:
#  1) In KDC_REQ/KDC_REP packets, the PA_Data is optional and needs a bit of "lookahead."
#       KRB_PA_Data_Optional -> KRB_PA_Data_Optional_Contents -> KRB_PA_Data_Sequence
#
#  2) Once we get to the KRB_PA_Data_Sequence level:
#  	KRB_PA_Data_Sequence -> KRB_PA_Data_Container -> KRB_PA_Data -> KRB_PA_Data_Element


# Encapsulating header #1 for KDC_REQ/KDC_REP packets where the PADATA is optional.
type KRB_PA_Data_Optional(is_orig: bool, pkt_type: uint8, desired_index: uint8) = record {
	first_meta	: ASN1EncodingMeta;
	padata		: KRB_PA_Data_Optional_Contents(is_orig, has_padata, pkt_type, first_meta.length);
	next_meta	: ASN1OptionalEncodingMeta(has_padata, first_meta);
} &let {
	has_padata : bool = first_meta.index == desired_index;
};

# Encapsulating header #2 for KDC_REQ/KDC_REP packets where the PADATA is optional.
#
# Note: Split off due to a BinPAC bug
type KRB_PA_Data_Optional_Contents(is_orig: bool, is_present: bool, pkt_type: uint8, length: uint64) = case is_present of {
	true -> padata	: KRB_PA_Data_Sequence(is_orig, pkt_type) &length=length;
	false -> none	: empty;
};

# This is our main type
type KRB_PA_Data_Sequence(is_orig: bool, pkt_type: uint8) = record {
	meta    : ASN1EncodingMeta;
	data	: KRB_PA_Data_Container(is_orig, pkt_type, meta.tag, meta.length);
};

# The data in KRB_PA_Data_Sequence is usually (and supposed to be) a sequence, which we'll parse,
# but is sometimes an octet string. We'll grab that but ignore it.
#
# Note: This is a separate type due to a BinPAC bug.
type KRB_PA_Data_Container(is_orig: bool, pkt_type: uint8, tag: uint8, length: uint64) = case tag of {
	ASN1_SEQUENCE_TAG	-> padata_elems	: KRB_PA_Data(is_orig, pkt_type)[];
	default 		-> unknown	: bytestring &length=length;
} &let {
	has_padata: bool = (tag == ASN1_SEQUENCE_TAG);
};

# The pre-auth data sequence.
#
# Note: Error packets don't have pre-auth data, they just advertise which mechanisms they support.
type KRB_PA_Data(is_orig: bool, pkt_type: uint8) = record {
	seq_meta	  : ASN1EncodingMeta;
	pa_data_type      : SequenceElement(true);
	pa_data_elem_meta : ASN1EncodingMeta;
	have_data	  : case pkt_type of {
		KRB_ERROR   -> pa_data_placeholder: bytestring &length=pa_data_elem_meta.length;
		default	    -> pa_data_element : KRB_PA_Data_Element(is_orig, data_type, pa_data_elem_meta.length);
	} &requires(data_type);
} &let {
	data_type: int64 = binary_to_int64(pa_data_type.data.content);
};

# Each pre-auth element
type KRB_PA_Data_Element(is_orig: bool, type: int64, length: uint64) = case type of {
	PA_TGS_REQ       -> pa_tgs_req	: KRB_PA_AP_REQ_wrapper(is_orig);
	PA_PW_SALT       -> pa_pw_salt	: ASN1OctetString;
	PA_PW_AS_REQ	   -> pa_pk_as_req	: KRB_PA_PK_AS_Req &length=length;
	PA_PW_AS_REP	   -> pa_pk_as_rep	: KRB_PA_PK_AS_Rep &length=length;
	PA_ENCTYPE_INFO  -> pf_enctype_info	: KRB_PA_ENCTYPE_INFO &length=length;
	PA_ENCTYPE_INFO2 -> pf_enctype_info2: KRB_PA_ENCTYPE_INFO &length=length;
	default 	-> unknown	: ASN1Encoding &length=length;
};

type KRB_PA_AP_REQ_wrapper(is_orig: bool) = record {
	# Not sure what these two field are, but they need to be 
	# here for pre-auth ap-req messages.
	some_meta1 : ASN1EncodingMeta;
	some_meta2 : ASN1EncodingMeta;
	req        : KRB_AP_REQ(is_orig);
};

# The PKINIT certificate structure for a request
type KRB_PA_PK_AS_Req = record {
	string_meta	: ASN1EncodingMeta;
	seq_meta1	: ASN1EncodingMeta;
	elem_0_meta1	: ASN1EncodingMeta;
	seq_meta2	: ASN1EncodingMeta;
	oid		: ASN1Encoding;
	elem_0_meta2	: ASN1EncodingMeta;
	seq_meta3	: ASN1EncodingMeta;
	version		: ASN1Encoding;
	digest_algs	: ASN1Encoding;
	signed_data	: ASN1Encoding;
	cert_meta	: ASN1EncodingMeta;
	cert		: bytestring &length=cert_meta.length;
	# Ignore everything else
			: bytestring &restofdata &transient;
};

# The PKINIT certificate structure for a reply
type KRB_PA_PK_AS_Rep = record {
	string_meta 	: ASN1EncodingMeta;
	elem_0_meta1	: ASN1EncodingMeta;
	seq_meta1	: ASN1EncodingMeta;
	elem_0_meta2	: ASN1EncodingMeta;
	seq_meta2	: ASN1EncodingMeta;
	oid		: ASN1Encoding;
	elem_0_meta3	: ASN1EncodingMeta;
	seq_meta3	: ASN1EncodingMeta;
	version		: ASN1Encoding;
	digest_algs	: ASN1Encoding;
	signed_data	: ASN1Encoding;
	cert_meta	: ASN1EncodingMeta;
	cert		: bytestring &length=cert_meta.length;
	# Ignore everything else
			: bytestring &restofdata &transient;
};

type KRB_PA_ENCTYPE_INFO = record {
	some_meta1  : ASN1EncodingMeta;
	some_meta2  : ASN1EncodingMeta;
	seq_meta1   : ASN1EncodingMeta;
	etype       : ASN1Encoding;
	optional_seq_meta2: case has_string of {
		true  -> seq_meta2: ASN1EncodingMeta;
		false -> nil1: empty;
	};
	optional_string_meta: case has_string of {
		true  -> string_meta: ASN1EncodingMeta;
		false -> nil2: empty;
		};
	salt: bytestring &length=salt_length;
} &let {
	has_string: bool = (some_meta2.length > 7);
	salt_length: uint32 = has_string ? string_meta.length : 0;
};
