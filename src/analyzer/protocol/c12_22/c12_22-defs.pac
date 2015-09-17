# Defined in IEEE 1703-2012 Annex J
enum ASCEPDUTypes {
	Protocol_Version         = 0,
	ASO_Context              = 1,
	Called_AP_Title          = 2,
	Called_AE_Qualifier      = 3,
	Called_AP_Invocation_ID  = 4,
	Called_AE_Invocation_ID  = 5,
	Calling_AE_Title         = 6,
	Calling_AP_Qualifier     = 7,
	Calling_AP_Invocation_ID = 8,
	Calling_AE_Invocation_ID = 9,

	Mechanism_Name           = 11,
	Calling_Auth_Value       = 12,

	P_Context                = 14,

	Implementation_Info      = 29,
	User_Information         = 30,
};

enum EPSEMRequestCodes {
	Request_Ident          = 0x20,
	Request_Terminate      = 0x21,
	Request_Disconnect     = 0x22,
	Request_Deregistration = 0x24,
	Request_Resolve        = 0x25,
	Request_Trace          = 0x26,
	Request_Registration   = 0x27,
	
	Request_Read_Full    = 0x30,
	Request_Read_Index_1 = 0x31,
	Request_Read_Index_2 = 0x32,
	Request_Read_Index_3 = 0x33,
	Request_Read_Index_4 = 0x34,
	Request_Read_Index_5 = 0x35,
	Request_Read_Index_6 = 0x36,
	Request_Read_Index_7 = 0x37,
	Request_Read_Index_8 = 0x38,
	Request_Read_Index_9 = 0x39,
	Request_Read_Default = 0x3e,
	Request_Read_Offset  = 0x3f,
	
	Request_Write_Full    = 0x40,
	Request_Write_Index_1 = 0x41,
	Request_Write_Index_2 = 0x42,
	Request_Write_Index_3 = 0x43,
	Request_Write_Index_4 = 0x44,
	Request_Write_Index_5 = 0x45,
	Request_Write_Index_6 = 0x46,
	Request_Write_Index_7 = 0x47,
	Request_Write_Index_8 = 0x48,
	Request_Write_Index_9 = 0x49,
	Request_Write_Offset  = 0x4f,

	Request_Logon    = 0x50,
	Request_Security = 0x51,
	Request_Logoff   = 0x52,
	
	Request_Wait = 0x70,
};

enum EPSEMResponseCodes {
	Response_OK    = 0x0,
	Response_ERR   = 0x1,
	Response_SNS   = 0x2,
	Response_ISC   = 0x3,
	Response_ONP   = 0x4,

	Response_IAR   = 0x5,
	Response_BSY   = 0x6,
	Response_DNR   = 0x7,
	Response_DLK   = 0x8,
	Response_RNO   = 0x9,

	Response_ISSS  = 0xa,
	Response_SME   = 0xb,
	Response_UAT   = 0xc,
	Response_NETT  = 0xd,
	Response_NETR  = 0xe,

	Response_RQTL  = 0xf,
	Response_RSTL  = 0x10,
	Response_SGNP  = 0x11,
	Response_SGERR = 0x12,
};