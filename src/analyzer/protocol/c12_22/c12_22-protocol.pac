# ASN1 parsing
%include ../asn1/asn1.pac

%include c12_22-defs.pac

type C12_22_PDU(is_orig: bool) = record {
	acse_meta : ASN1EncodingMeta;
	acse_args : ACSE_Arg(is_orig)[];
} &byteorder=bigendian;

type ACSE_Arg(is_orig: bool) = record {
	seq_meta : ASN1EncodingMeta;
	data     : ACSE_Arg_Data(seq_meta.index) &length=seq_meta.length;
};

type ACSE_Arg_Data(index: uint8) = case index of {
	Protocol_Version         -> version                  : ASN1Integer;
	# ASO_Context            -> aso_context              : NOT_IMPLEMENTED;
	# Called_AP_Title        -> called_ap_title          : NOT_IMPLEMENTED;
	Called_AE_Qualifier      -> called_ae_qualifier      : ASN1Integer;
	Called_AP_Invocation_ID  -> called_ap_invocation_id  : ASN1Integer;
	Called_AE_Invocation_ID  -> called_ae_invocation_id  : ASN1Integer;
	# Calling_AE_Title       -> calling_ae_title         : NOT_IMPLEMENTED;
	Calling_AP_Qualifier     -> calling_ap_qualifier     : ASN1Integer;
	Calling_AP_Invocation_ID -> calling_ap_invocation_id : ASN1Integer;
	Calling_AE_Invocation_ID -> calling_ae_invocation_id : ASN1Integer;
	# Mechanism_Name         -> mechanism_name           : NOT_IMPLEMENTED;
	# Calling_Auth_Value     -> calling_auth_value       : NOT_IMPLEMENTED;
	# P_Context              -> p_context                : NOT_IMPLEMENTED;
	# Implementation_Info    -> calling_auth_value       : NOT_IMPLEMENTED;
	User_Information         -> user_information         : C12_22_EPSEM &restofdata;
	default                  -> unknown                  : bytestring &restofdata;
};

type C12_22_EPSEM_Data = record {
	svc_length: uint8;
	msg       : C12_22_EPSEM_Msg &length=svc_length;
};

type C12_22_EPSEM_Msg = record {
	code : uint8;
	todo : bytestring &restofdata;
};

type C12_22_EPSEM = record {
	seq_meta     : ASN1EncodingMeta;
	ext_meta     : ASN1EncodingMeta;
	epsem_control: uint8;
	have_ed_class: case ed_class_included of {
		true  -> ed_class : uint32;
		false -> ignore: empty;
	};
	msgs         : C12_22_EPSEM_Data[];
} &let {
	recovery_session   : bool  = (epsem_control & 0x40) > 0;
	proxy_service_used : bool  = (epsem_control & 0x20) > 0;
	ed_class_included  : bool  = (epsem_control & 0x10) > 0;
	security_mode      : uint8 =  epsem_control & 0x0c;
	response_control   : uint8 =  epsem_control & 0x03;
};


