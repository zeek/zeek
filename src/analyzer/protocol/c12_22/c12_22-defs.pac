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