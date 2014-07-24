#include "plugin/Plugin.h"

#include "SMB.h"

BRO_PLUGIN_BEGIN(Bro, SMB)
	BRO_PLUGIN_DESCRIPTION("SMB analyzer");
	BRO_PLUGIN_ANALYZER("SMB", smb::SMB_Analyzer);
	BRO_PLUGIN_SUPPORT_ANALYZER("Contents_SMB");
	BRO_PLUGIN_BIF_FILE(smb1_events);
	BRO_PLUGIN_BIF_FILE(smb2_events);

	BRO_PLUGIN_BIF_FILE(smb_ntlmssp);
	BRO_PLUGIN_BIF_FILE(smb_pipe);

	BRO_PLUGIN_BIF_FILE(types);

	BRO_PLUGIN_BIF_FILE(smb1_com_check_directory);
	BRO_PLUGIN_BIF_FILE(smb1_com_close);
	BRO_PLUGIN_BIF_FILE(smb1_com_create_directory);
	BRO_PLUGIN_BIF_FILE(smb1_com_echo);
	BRO_PLUGIN_BIF_FILE(smb1_com_logoff_andx);
	BRO_PLUGIN_BIF_FILE(smb1_com_negotiate);
	BRO_PLUGIN_BIF_FILE(smb1_com_nt_create_andx);
	BRO_PLUGIN_BIF_FILE(smb1_com_nt_cancel);
	BRO_PLUGIN_BIF_FILE(smb1_com_query_information);
	BRO_PLUGIN_BIF_FILE(smb1_com_read_andx);
	BRO_PLUGIN_BIF_FILE(smb1_com_session_setup_andx);
	BRO_PLUGIN_BIF_FILE(smb1_com_tree_connect_andx);
	BRO_PLUGIN_BIF_FILE(smb1_com_tree_disconnect);
	BRO_PLUGIN_BIF_FILE(smb1_com_write_andx);

	BRO_PLUGIN_BIF_FILE(smb2_com_close);
	BRO_PLUGIN_BIF_FILE(smb2_com_create);
	BRO_PLUGIN_BIF_FILE(smb2_com_negotiate);
	BRO_PLUGIN_BIF_FILE(smb2_com_read);
	BRO_PLUGIN_BIF_FILE(smb2_com_session_setup);
	BRO_PLUGIN_BIF_FILE(smb2_com_tree_connect);
	BRO_PLUGIN_BIF_FILE(smb2_com_tree_disconnect);
	BRO_PLUGIN_BIF_FILE(smb2_com_write);

BRO_PLUGIN_END
