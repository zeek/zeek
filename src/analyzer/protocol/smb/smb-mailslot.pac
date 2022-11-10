enum SMB_MailSlot_opcode {
	HOST_ANNOUNCEMENT		= 1,
	ANNOUNCEMENT_REQUEST	= 2,
	REQUEST_ELECTION		= 8,
	GET_BACKUP_LIST_REQUEST = 9,
	GET_BACKUP_LIST_RESPONSE	= 10,
	BECOME_BACKUP_REQUEST		= 11, #uncommon
	DOMAIN_ANNOUNCEMENT		= 12,
	MASTER_ANNOUNCEMENT	= 13, #uncommon
	RESET_BROWSER_STATE	= 14, #uncommon
	LOCAL_MASTER_ANNOUNCEMENT = 15,
};

type SMB_MailSlot_message( unicode: bool, byte_count: uint16 ) = record {

	opcode : uint8;
	data : SMB_MailSlot_command( unicode, opcode, byte_count );

} &byteorder = littleendian;

type SMB_MailSlot_command(unicode: bool, code: uint8, byte_count: uint16 ) = case code of {
	HOST_ANNOUNCEMENT		-> announce : SMB_MailSlot_host_announcement(unicode);
	ANNOUNCEMENT_REQUEST	-> announce_req : SMB_MailSlot_announcement_request(unicode);
	REQUEST_ELECTION		-> election_req : SMB_MailSlot_request_election(unicode);
	GET_BACKUP_LIST_REQUEST -> get_backup_req : SMB_MailSlot_get_backup_list_request(unicode);
	GET_BACKUP_LIST_RESPONSE	-> get_backup_resp : SMB_MailSlot_get_backup_list_response(unicode);
	DOMAIN_ANNOUNCEMENT		-> domain_announce : SMB_MailSlot_domain_announcement(unicode);
	LOCAL_MASTER_ANNOUNCEMENT -> lm_announce : SMB_MailSlot_local_master_announcement(unicode);
	default -> data : bytestring &restofdata;
} &byteorder = littleendian;

type SMB_MailSlot_host_announcement(unicode: bool) = record {
	update_count : uint8;
	periodicity : uint32;
	server_name : SMB_string(unicode, offsetof(server_name));
	os_major_ver : uint8;
	os_minor_ver : uint8;
	server_type : uint32;
	bro_major_ver : uint8;
	bro_minor_ver : uint8;
	signature : uint16;
	comment : SMB_string(unicode, offsetof(comment));
} &byteorder = littleendian;

type SMB_MailSlot_announcement_request(unicode: bool) = record {
	unused : uint8;
	response_name : SMB_string(unicode, offsetof(response_name));
} &byteorder = littleendian;

type SMB_MailSlot_request_election(unicode: bool) = record {
	version : uint8;
	criteria : uint32;
	uptime : uint32;
	reserved : uint32;
	server_name : SMB_string(unicode, offsetof(server_name));
} &byteorder = littleendian;

type SMB_MailSlot_get_backup_list_request(unicode: bool) = record {
	req_count : uint8;
	token : uint32;
} &byteorder = littleendian;

type SMB_MailSlot_get_backup_list_response(unicode: bool) = record {
	backup_count : uint8;
	token : uint32;
	backup_list : SMB_string(unicode, offsetof(backup_list));
} &byteorder = littleendian;

type SMB_MailSlot_domain_announcement(unicode: bool) = record {
	update_count : uint8;
	periodicity : uint32;
	server_name : SMB_string(unicode, offsetof(server_name));
	os_major_ver : uint8;
	os_minor_ver : uint8;
	server_type : uint32;
	bro_major_ver : uint8;
	bro_minor_ver : uint8;
	signature : uint16;
	comment : SMB_string(unicode, offsetof(comment));
} &byteorder = littleendian;

type SMB_MailSlot_local_master_announcement(unicode: bool) = record {
	update_count : uint8;
	periodicity : uint32;
	server_name : SMB_string(unicode, offsetof(server_name));
	os_major_ver : uint8;
	os_minor_ver : uint8;
	server_type : uint32;
	bro_major_ver : uint8;
	bro_minor_ver : uint8;
	signature : uint16;
	comment : SMB_string(unicode, offsetof(comment));
} &byteorder = littleendian;
