##### Moved from dnp3-protocol.pac

type Prefix_Type(qualifier_field: uint8) = record {
	prefix: case ( qualifier_field & 0xf0 ) of {
		0x00 -> none: empty;
		0x10 -> prefix8: uint8; # &check(qualifier_field == 0x17 || qualifier_field == 0x18 || qualifier_field == 0x19 );
		0x20 -> prefix16: uint16; # &check(qualifier_field == 0x27 || qualifier_field == 0x28 || qualifier_field == 0x29 );
		0x30 -> prefix32: uint32; # &check(qualifier_field == 0x37 || qualifier_field == 0x38 || qualifier_field == 0x39 );
		0x40 -> object_size8: uint8; # &check(qualifier_field == 0x4B);
		0x50 -> object_size16: uint16; # &check(qualifier_field == 0x5B);
		0x60 -> object_size32: uint32; # &check(qualifier_field == 0x6B);
	 	default -> unknownprefix: empty;
	};
} &let{
	prefix_value: uint32 = case (qualifier_field & 0xf0) of {
		0x00 -> 0;
		0x10 -> prefix8;
		0x20 -> prefix16;
		0x30 -> prefix32;
		0x40 -> object_size8;
		0x50 -> object_size16;
		0x60 -> object_size32;
		default -> 0x0;
	};
} &byteorder = littleendian;

type Request_Data_Object(function_code: uint8, qualifier_field: uint8, object_type_field: uint16) = record {
	prefix: Prefix_Type(qualifier_field);
	data: case (object_type_field) of {
	# device attributes g0
		0x00D3 -> attrib211: AttributeCommon;
		0x00D4 -> attrib212: AttributeCommon;
		0x00D5 -> attrib213: AttributeCommon;
		0x00D6 -> attrib214: AttributeCommon;
		0x00D7 -> attrib215: AttributeCommon;
		0x00D8 -> attrib216: AttributeCommon;
		0x00D9 -> attrib217: AttributeCommon;
		0x00DA -> attrib218: AttributeCommon;
		0x00DB -> attrib219: AttributeCommon;
		0x00DC -> attrib220: AttributeCommon;
		0x00DD -> attrib221: AttributeCommon;
		0x00DE -> attrib222: AttributeCommon;
		0x00DF -> attrib223: AttributeCommon;
		0x00E0 -> attrib224: AttributeCommon;
		0x00E1 -> attrib225: AttributeCommon;
		0x00E2 -> attrib226: AttributeCommon;
		0x00E3 -> attrib227: AttributeCommon;
		0x00E4 -> attrib228: AttributeCommon;
		0x00E5 -> attrib229: AttributeCommon;
		0x00E6 -> attrib230: AttributeCommon;
		0x00E7 -> attrib231: AttributeCommon;
		0x00E8 -> attrib232: AttributeCommon;
		0x00E9 -> attrib233: AttributeCommon;
		0x00EA -> attrib234: AttributeCommon;
		0x00EB -> attrib235: AttributeCommon;
		0x00EC -> attrib236: AttributeCommon;
		0x00ED -> attrib237: AttributeCommon;
		0x00EE -> attrib238: AttributeCommon;
		0x00EF -> attrib239: AttributeCommon;
		0x00F0 -> attrib240: AttributeCommon;
		0x00F1 -> attrib241: AttributeCommon;
		0x00F2 -> attrib242: AttributeCommon;
		0x00F3 -> attrib243: AttributeCommon;
		0x00F5 -> attrib245: AttributeCommon;
		0x00F6 -> attrib246: AttributeCommon;
		0x00F7 -> attrib247: AttributeCommon;
		0x00F8 -> attrib248: AttributeCommon;
		0x00F9 -> attrib249: AttributeCommon;
		0x00FA -> attrib250: AttributeCommon;
		0x00FC -> attrib252: AttributeCommon;
		0x00FE -> attrib254: AttributeCommon;
		0x00FF -> attrib255: AttributeCommon;

	# binary input g1
		0x0100 -> bi_default: empty;
		0x0101 -> bi_packed: empty;
		0x0102 -> bi_flag: empty;

	# binary input event g2
		0x0200 -> biedefault: empty;
		0x0201 -> biewotime: empty;
		0x0202 -> biewatime: empty;
		0x0203 -> biewrtime: empty;

	# double-bit Binary Input g3
		0x0300 -> dbiDefault: empty;
		0x0301 -> dbibytes: empty;
		0x0302 -> dbiflag: empty;

	# double-bit Binary Input Event g4
		0x0400 -> dbieDefault: empty;
		0x0401 -> dbieatime: empty;
		0x0402 -> dbiertime: empty;

	# binary output g10
		0x0a00 -> boDefault: empty;
		0x0a01 -> bowoflag: empty;  # warning: returning integer index?
		0x0a02 -> bowflag: empty;  # warning: only flag?

	# binary output event g11
		0x0b00 -> bowDefault: empty;
		0x0b01 -> boewflag: empty;
		0x0b02 -> boewatime: empty;

	# binary output command g12
		0x0c01 -> bocmd_CROB: CROB; # &check (function_code == RESPONSE || function_code == SELECT || function_code == OPERATE || function_code == DIRECT_OPERATE || function_code == DIRECT_OPERATE_NR );
		0x0c02 -> bocmd_PCB: PCB; # &check (function_code == RESPONSE || function_code == SELECT || function_code == OPERATE || function_code == DIRECT_OPERATE || function_code == DIRECT_OPERATE_NR || function_code == WRITE );
		0x0c03 -> bocmd_PM: uint8;

	# binary output command event g13
		0x0d00 -> boceDefault: empty;
		0x0d01 -> boceFlag: empty;
		0x0d02 -> boceAtime: empty;

	# counter ; g20
		0x1400 -> counter_default: empty;
		0x1401 -> counter_32_wflag: empty;
		0x1402 -> counter_16_wflag: empty;
		0x1403 -> counter_32_wflag_delta: empty; # obsolete situation; generate warning
		0x1404 -> counter_16_wflag_delta: empty; # obsolete situations; generate warning
		0x1405 -> counter_32_woflag: empty;
		0x1406 -> counter_16_woflag: empty;
		0x1407 -> counter_32_woflag_delta: empty; # obsolete
		0x1408 -> counter_16_woflag_delta: empty; # obsolete
	# frozen counter ; g21
		0x1500 -> f_counter_default: empty;
		0x1501 -> f_counter_32_wflag: empty;
		0x1502 -> f_counter_16_wflag: empty;
		0x1503 -> f_counter_32_wflag_delta: empty; # obsolete situation; generate warning
		0x1504 -> f_counter_16_wflag_delta: empty; # obsolete situations; generate warning
		0x1505 -> f_counter_32_wflag_time: empty;
		0x1506 -> f_counter_16_wflag_time: empty;
		0x1507 -> f_counter_32_wflag_time_delta: empty; # obsolete
		0x1508 -> f_counter_16_wflag_time_delta: empty; # obsolete
		0x1509 -> f_counter_32_woflag: empty;
		0x150a -> f_counter_16_woflag: empty;
		0x150b -> f_counter_32_woflag_delta: empty; # obsolete
		0x150c -> f_counter_16_woflag_delta: empty; # obsolete

	# counter event g22
		0x1600 -> counter_event_default: empty;
		0x1601 -> counter_event_32_wflag: empty;
		0x1602 -> counter_event_16_wflag: empty;
		0x1603 -> counter_event_32_wflag_delta: empty;
		0x1604 -> counter_event_16_wflag_delta: empty;
		0x1605 -> counter_event_32_wflag_time: empty;
		0x1606 -> counter_event_16_wflag_time: empty;
		0x1607 -> counter_event_32_wflag_time_delta: empty;
		0x1608 -> counter_event_16_wflag_time_delat: empty;

	# counter event g23
		0x1700 -> f_counter_event_default: empty;
		0x1701 -> f_counter_event_32_wflag: empty;
		0x1702 -> f_counter_event_16_wflag: empty;
		0x1703 -> f_counter_event_32_wflag_delta: empty;
		0x1704 -> f_counter_event_16_wflag_delta: empty;
		0x1705 -> f_counter_event_32_wflag_time: empty;
		0x1706 -> f_counter_event_16_wflag_time: empty;
		0x1707 -> f_counter_event_32_wflag_time_delta: empty;
		0x1708 -> f_counter_event_16_wflag_time_delat: empty;

	#analog input g30
		0x1e00 -> ai_default: empty;
		0x1e01 -> ai_32_wflag: empty;
		0x1e02 -> ai_16_wflag: empty;
		0x1e03 -> ai_32_woflag: empty;
		0x1e04 -> ai_16_woflag: empty;
		0x1e05 -> ai_sp_wflag: empty;
		0x1e06 -> ai_dp_wflag: empty;

	#frozen analog input g31
		0x1f00 -> f_ai_default: empty;
		0x1f01 -> f_ai_32_wflag: empty;
		0x1f02 -> f_ai_16_wflag: empty;
		0x1f03 -> f_ai_32_wtime: empty;
		0x1f04 -> f_ai_16_wtime: empty;
		0x1f05 -> f_ai_32_woflag: empty;
		0x1f06 -> f_ai_16_woflag: empty;
		0x1f07 -> f_ai_sp_wflag: empty;
		0x1f08 -> f_ai_dp_wflag: empty;

	#analog input event g32
		0x2000 -> aie_default: empty;
		0x2001 -> ai32wotime: empty;
		0x2002 -> ai16wotime: empty;
		0x2003 -> ai32wtime:  empty;
		0x2004 -> ai16wtime:  empty;
		0x2005 -> aispwotime: empty;
		0x2006 -> aidpwotime: empty;
		0x2007 -> aispwtime:  empty;
		0x2008 -> aidpwtime:  empty;

	# frozen analog input g33
		0x2100 -> f_aie_default: empty;
		0x2101 -> f_aie_32_wotime: empty;
		0x2102 -> f_aie_16_wotime: empty;
		0x2103 -> f_aie_32_wtime: empty;
		0x2104 -> f_aie_16_wtime: empty;
		0x2105 -> f_aie_sp_wotime: empty;
		0x2106 -> f_aie_dp_wotime: empty;
		0x2107 -> f_aie_sp_wtime: empty;
		0x2108 -> f_aie_dp_wtime: empty;

	# analog input deadband g34
		0x2200 -> ai_dead: empty;
		0x2201 -> ai_dead_16: empty;
		0x2202 -> ai_dead_32: empty;
		0x2203 -> ai_dead_sp: empty;

	# analog output status g40
		0x2800 -> aos_default: empty;
		0x2801 -> aos_32: empty;
		0x2802 -> aos_16: empty;
		0x2803 -> aos_sp: empty;
		0x2804 -> aos_dp: empty;

	# analog output g41
		0x2901 -> ao_32: empty;
		0x2902 -> ao_16: empty;
		0x2903 -> ao_sp: empty;
		0x2904 -> ao_dp: empty;

	# analog output event g42
		0x2a00 -> aoe_default: empty;
		0x2a01 -> aoe32wotime: empty;
		0x2a02 -> aoe16wotime: empty;
		0x2a03 -> aoe32wtime:  empty;
		0x2a04 -> aoe16wtime:  empty;
		0x2a05 -> aoespwotime: empty;
		0x2a06 -> aoedpwotime: empty;
		0x2a07 -> aoespwtime:  empty;
		0x2a08 -> aoedpwtime:  empty;

	# analog output command event g43
		0x2b00 -> aoce_default: empty;
		0x2b01 -> aoce32wotime: empty;
		0x2b02 -> aoce16wotime: empty;
		0x2b03 -> aoce32wtime:  empty;
		0x2b04 -> aoce16wtime:  empty;
		0x2b05 -> aocespwotime: empty;
		0x2b06 -> aocedpwotime: empty;
		0x2b07 -> aocespwtime:  empty;
		0x2b08 -> aocedpwtime:  empty;

	# time data interval data object g50
		0x3200 -> time_default: empty;
		0x3201 -> time_abs: AbsTime;
		0x3202 -> time_interval: AbsTimeInterval;
		0x3203 -> time_abs_last: Last_AbsTime;

	# Time and Date Common Time-of-Occurrence g51
		0x3301 -> time_abs_sync: AbsTime;
		0x3302 -> time_abs_unsync: AbsTime;

	# time delay g52
		0x3401 -> time_coarse: uint16;
		0x3402 -> time_fine: uint16;

	# class objects g60
		0x3C01 -> class0data: empty; # &check(qualifier_field == 0x06);
		0x3C02 -> class1data: empty; # &check(qualifier_field == 0x06 || qualifier_field == 0x07 || qualifier_field == 0x08);
		0x3C03 -> class2data: empty; # &check(qualifier_field == 0x06 || qualifier_field == 0x07 || qualifier_field == 0x08);
		0x3C04 -> class3data: empty; # &check(qualifier_field == 0x06 || qualifier_field == 0x07 || qualifier_field == 0x08);
	# file control g70
		0x4601 -> file_control_id: File_Control_ID;
		0x4602 -> file_control_auth: File_Control_Auth_Wrap(function_code);
		0x4603 -> file_control_cmd: File_Control_Cmd; # &check( file_control_cmd.op_mode == 0 || file_control_cmd.op_mode == 1 || file_control_cmd.op_mode == 2 || file_control_cmd.op_mode == 3 );
		0x4604 -> file_control_cmd_status: File_Control_Cmd_Status(prefix.prefix_value);  # example shown in P66
		0x4605 -> file_trans: File_Transport(prefix.prefix_value);
		0x4606 -> file_trans_status: File_Transport_Status(prefix.prefix_value);
		0x4607 -> file_desc: File_Desc;

	# internal indication g80
		#0x5001 -> iin: uint16;
		0x5001 -> iin: bytestring &restofdata; # confusion from the real traffic

	# device storage g81
		0x5101 -> dev_store: empty;

	# device storage g82
		0x5201 -> dev_profile: empty;

	# device storage g83
		0x5301 -> priregobj: PrivRegObj;
		0x5302 -> priregobjdesc: PrivRegObjDesc;

	# private data set g85
		0x5501 -> desc_ele: DescEle;

	# data descriptor table g86
		0x5601 -> desc_ele86: DescEle;
		0x5602 -> cha: uint8;
		0x5603 -> point_index_attr: Debug_Byte;

	# Data set g87
		0x5701 -> present_value: Debug_Byte;

	# Data set event g88
		0x5801 -> snapshot: Debug_Byte;

	# application identification object g90
		#0x5A01 -> app_id: App_Id(qualifier_field, object_size16);
		#0x5A01 -> app_id: App_Id(qualifier_field, prefix.prefix_value);

	# status of request operation g91
		0x5b01 -> activate_conf: ActivateConf;

	# bcd value g101
		0x6501 -> bcd_small: uint16;
		0x6502 -> bcd_medium: uint32;
		0x6503 -> bcd_large: BCD_Large;

	# unsigned integer g102
		0x6601 -> unsigned_integer: uint8;

	# authentication challenge g120
		0x7801 -> challenge: AuthChallenge(prefix.prefix_value);
		0x7802 -> reply: AuthReply(prefix.prefix_value);
		0x7803 -> aggrRequest: AuthAggrRequest(prefix.prefix_value);
		0x7804 -> sessionKeyRequest: uint16;
		0x7805 -> status: AuthSessionKeyStatus(prefix.prefix_value);
		0x7806 -> keyChange: AuthSessionKeyChange(prefix.prefix_value);
		0x7807 -> error: AuthError(prefix.prefix_value);
		0x7808 -> user_cert: UserCert(prefix.prefix_value);
		0x7809 -> mac: MAC(prefix.prefix_value);
		0x780A -> user_status_change: UserStatusChange(prefix.prefix_value);
		0x780B -> update_key_req: UpdateKeyReq(prefix.prefix_value);
		0x780C -> update_key_rep: UpdateKeyRep(prefix.prefix_value);
		0x780D -> update_key: UpdateKey(prefix.prefix_value);
		0x780E -> update_key_sig: UpdateKeySig(prefix.prefix_value);
		0x780F -> update_key_con: UpdateKeyCon(prefix.prefix_value);
		default -> unmatched: Default_Wrap(object_type_field);
	};
};


type Response_Data_Object(function_code: uint8, qualifier_field: uint8, object_type_field: uint16) = record {
	prefix: Prefix_Type(qualifier_field);
	data: case (object_type_field) of {
	# device attributes g0
		0x00D3 -> attrib211: AttributeCommon;
		0x00D4 -> attrib212: AttributeCommon;
		0x00D5 -> attrib213: AttributeCommon;
		0x00D6 -> attrib214: AttributeCommon;
		0x00D7 -> attrib215: AttributeCommon;
		0x00D8 -> attrib216: AttributeCommon;
		0x00D9 -> attrib217: AttributeCommon;
		0x00DA -> attrib218: AttributeCommon;
		0x00DB -> attrib219: AttributeCommon;
		0x00DC -> attrib220: AttributeCommon;
		0x00DD -> attrib221: AttributeCommon;
		0x00DE -> attrib222: AttributeCommon;
		0x00DF -> attrib223: AttributeCommon;
		0x00E0 -> attrib224: AttributeCommon;
		0x00E1 -> attrib225: AttributeCommon;
		0x00E2 -> attrib226: AttributeCommon;
		0x00E3 -> attrib227: AttributeCommon;
		0x00E4 -> attrib228: AttributeCommon;
		0x00E5 -> attrib229: AttributeCommon;
		0x00E6 -> attrib230: AttributeCommon;
		0x00E7 -> attrib231: AttributeCommon;
		0x00E8 -> attrib232: AttributeCommon;
		0x00E9 -> attrib233: AttributeCommon;
		0x00EA -> attrib234: AttributeCommon;
		0x00EB -> attrib235: AttributeCommon;
		0x00EC -> attrib236: AttributeCommon;
		0x00ED -> attrib237: AttributeCommon;
		0x00EE -> attrib238: AttributeCommon;
		0x00EF -> attrib239: AttributeCommon;
		0x00F0 -> attrib240: AttributeCommon;
		0x00F1 -> attrib241: AttributeCommon;
		0x00F2 -> attrib242: AttributeCommon;
		0x00F3 -> attrib243: AttributeCommon;
		0x00F5 -> attrib245: AttributeCommon;
		0x00F6 -> attrib246: AttributeCommon;
		0x00F7 -> attrib247: AttributeCommon;
		0x00F8 -> attrib248: AttributeCommon;
		0x00F9 -> attrib249: AttributeCommon;
		0x00FA -> attrib250: AttributeCommon;
		0x00FC -> attrib252: AttributeCommon;
		0x00FE -> attrib254: AttributeCommon;
		0x00FF -> attrib255: AttributeCommon;

	# binary input g1
		0x0101 -> biwoflag: uint8;  # warning: returning integer index?
		0x0102 -> biwflag: uint8;  # warning: only flag?

	# binary input event g2
		0x0201 -> biewoflag: uint8;
		0x0202 -> biewatime: BinInEveAtime;
		0x0203 -> biewrtime: BinInEveRtime;

	# double-bit Binary Input g3
		0x0301 -> dbibytes: bytestring &restofdata; # don;t quit understand specification
		0x0302 -> dbiflag: uint8;

	# double-bit Binary Input Event g4
		0x0401 -> dbieatime: DoubleInEveAtime;
		0x0402 -> dbiertime: DoubleInEveRtime;

	# binary output g10
		0x0a01 -> bowoflag:  uint8;  # warning: returning integer index?
		0x0a02 -> bowflag: uint8;  # warning: only flag?

	# binary output event g11
		0x0b01 -> boewflag: uint8;
		0x0b02 -> boewatime: BinOutEveAtime;

	# binary output command g12
		0x0c01 -> bocmd_CROB: CROB; # &check (function_code == RESPONSE || function_code == SELECT || function_code == OPERATE || function_code == DIRECT_OPERATE || function_code == DIRECT_OPERATE_NR );
		0x0c02 -> bocmd_PCB: PCB; # &check (function_code == RESPONSE || function_code == SELECT || function_code == OPERATE || function_code == DIRECT_OPERATE || function_code == DIRECT_OPERATE_NR || function_code == WRITE );
		0x0c03 -> bocmd_PM: uint8;

	# binary output command event g13
		0x0d01 -> boceFlag: uint8;
		0x0d02 -> boceAtime: BinOutCmdEveAtime;

	# counter ; g20
		0x1401 -> counter_32_wflag: Counter32wFlag;
		0x1402 -> counter_16_wflag: Counter16wFlag;
		0x1403 -> counter_32_wflag_delta: Debug_Byte; # obsolete situation; generate warning
		0x1404 -> counter_16_wflag_delta: Debug_Byte; # obsolete situations; generate warning
		0x1405 -> counter_32_woflag: Counter32woFlag;
		0x1406 -> counter_16_woflag: Counter16woFlag;
		0x1407 -> counter_32_woflag_delta: Debug_Byte; # obsolete
		0x1408 -> counter_16_woflag_delta: Debug_Byte; # obsolete
	# frozen counter ; g21
		#0x1500 -> f_counter_default: empty;
		0x1501 -> f_counter_32_wflag: FrozenCounter32wFlag;
		0x1502 -> f_counter_16_wflag: FrozenCounter16wFlag;
		0x1503 -> f_counter_32_wflag_delta: Debug_Byte; # obsolete situation; generate warning
		0x1504 -> f_counter_16_wflag_delta: Debug_Byte; # obsolete situations; generate warning
		0x1505 -> f_counter_32_wflag_time: FrozenCounter32wFlagTime;
		0x1506 -> f_counter_16_wflag_time: FrozenCounter16wFlagTime;
		0x1507 -> f_counter_32_wflag_time_delta: Debug_Byte; # obsolete
		0x1508 -> f_counter_16_wflag_time_delta: Debug_Byte; # obsolete
		0x1509 -> f_counter_32_woflag: FrozenCounter32woFlag;
		0x150a -> f_counter_16_woflag: FrozenCounter16woFlag;
		0x150b -> f_counter_32_woflag_delta: Debug_Byte; # obsolete
		0x150c -> f_counter_16_woflag_delta: Debug_Byte; # obsolete

	# counter event g22
		0x1601 -> counter_event_32_wflag: CounterEve32wFlag;
		0x1602 -> counter_event_16_wflag: CounterEve16wFlag;
		0x1603 -> counter_event_32_wflag_delta: Debug_Byte;
		0x1604 -> counter_event_16_wflag_delta: Debug_Byte;
		0x1605 -> counter_event_32_wflag_time: CounterEve32wFlagTime;
		0x1606 -> counter_event_16_wflag_time: CounterEve16wFlagTime;
		0x1607 -> counter_event_32_wflag_time_delta: Debug_Byte;
		0x1608 -> counter_event_16_wflag_time_delat: Debug_Byte;

	# counter event g23
		0x1701 -> f_counter_event_32_wflag: CounterEve32wFlag;
		0x1702 -> f_counter_event_16_wflag: CounterEve16wFlag;
		0x1703 -> f_counter_event_32_wflag_delta: Debug_Byte;
		0x1704 -> f_counter_event_16_wflag_delta: Debug_Byte;
		0x1705 -> f_counter_event_32_wflag_time: CounterEve32wFlagTime;
		0x1706 -> f_counter_event_16_wflag_time: CounterEve16wFlagTime;
		0x1707 -> f_counter_event_32_wflag_time_delta: Debug_Byte;
		0x1708 -> f_counter_event_16_wflag_time_delat: Debug_Byte;

	# analog input g30
		0x1e01 -> ai_32_wflag: AnalogInput32wFlag;
		0x1e02 -> ai_16_wflag: AnalogInput16wFlag;
		0x1e03 -> ai_32_woflag: AnalogInput32woFlag;
		0x1e04 -> ai_16_woflag: AnalogInput16woFlag;
		0x1e05 -> ai_sp_wflag: AnalogInputSPwFlag;
		0x1e06 -> ai_dp_wflag: AnalogInputDPwFlag;

	# frozen analog input g31
		0x1f01 -> f_ai_32_wflag: FrozenAnalogInput32wFlag;
		0x1f02 -> f_ai_16_wflag: FrozenAnalogInput16wFlag;
		0x1f03 -> f_ai_32_wtime: FrozenAnalogInput32wTime;
		0x1f04 -> f_ai_16_wtime: FrozenAnalogInput16wTime;
		0x1f05 -> f_ai_32_woflag: FrozenAnalogInput32woFlag;
		0x1f06 -> f_ai_16_woflag: FrozenAnalogInput16woFlag;
		0x1f07 -> f_ai_sp_wflag: FrozenAnalogInputSPwFlag;
		0x1f08 -> f_ai_dp_wflag: FrozenAnalogInputDPwFlag;

	# analog input event g32
		0x2001 -> ai32wotime: AnalogInput32woTime;
		0x2002 -> ai16wotime: AnalogInput16woTime;
		0x2003 -> ai32wtime:  AnalogInput32wTime;
		0x2004 -> ai16wtime:  AnalogInput16wTime;
		0x2005 -> aispwotime: AnalogInputSPwoTime;
		0x2006 -> aidpwotime: AnalogInputDPwoTime;
		0x2007 -> aispwtime:  AnalogInputSPwTime;
		0x2008 -> aidpwtime:  AnalogInputDPwTime;

	# frozen analog input event g33
		0x2101 -> faie_32_wotime: FrozenAnaInputEve32woTime;
		0x2102 -> faie_16_wotime: FrozenAnaInputEve16woTime;
		0x2103 -> faie_32_wtime: FrozenAnaInputEve32wTime;
		0x2104 -> faie_16_wtime: FrozenAnaInputEve16wTime;
		0x2105 -> faie_sp_wotime: FrozenAnaInputEveSPwoTime;
		0x2106 -> faie_dp_wotime: FrozenAnaInputEveDPwoTime;
		0x2107 -> faie_sp_wtime: FrozenAnaInputEveSPwTime;
		0x2108 -> faie_dp_wtime: FrozenAnaInputEveDPwTime;

	# analog input deadband g34
		0x2201 -> ai_dead_16: uint16;
		0x2202 -> ai_dead_32: uint32;
		0x2203 -> ai_dead_sp: uint32;

	# analog output status g40
		0x2801 -> aos_32: AnaOutStatus32;
		0x2802 -> aos_16: AnaOutStatus16;
		0x2803 -> aos_sp: AnaOutStatusSP;
		0x2804 -> aos_dp: AnaOutStatusDP;

	# analog output g41
		0x2901 -> ao_32: AnaOut32;
		0x2902 -> ao_16: AnaOut16;
		0x2903 -> ao_sp: AnaOutSP;
		0x2904 -> ao_dp: AnaOutDP;

	# analog output event g42
		0x2a01 -> aoe32wotime: AnaOutEve32woTime;
		0x2a02 -> aoe16wotime: AnaOutEve16woTime;
		0x2a03 -> aoe32wtime:  AnaOutEve32wTime;
		0x2a04 -> aoe16wtime:  AnaOutEve16wTime;
		0x2a05 -> aoespwotime: AnaOutEveSPwoTime;
		0x2a06 -> aoedpwotime: AnaOutEveDPwoTime;
		0x2a07 -> aoespwtime:  AnaOutEveSPwTime;
		0x2a08 -> aoedpwtime:  AnaOutEveDPwTime;

	# analog output command event g43
		0x2b01 -> aoce32wotime: AnaOutEve32woTime;
		0x2b02 -> aoce16wotime: AnaOutEve16woTime;
		0x2b03 -> aoce32wtime:  AnaOutEve32wTime;
		0x2b04 -> aoce16wtime:  AnaOutEve16wTime;
		0x2b05 -> aocespwotime: AnaOutEveSPwoTime;
		0x2b06 -> aocedpwotime: AnaOutEveDPwoTime;
		0x2b07 -> aocespwtime:  AnaOutEveSPwTime;
		0x2b08 -> aocedpwtime:  AnaOutEveDPwTime;

 	# time data interval data object g50
		0x3201 -> time_abs: AbsTime;
		0x3202 -> time_interval: AbsTimeInterval;
		0x3203 -> time_abs_last: Last_AbsTime;

	# Time and Date Common Time-of-Occurrence g51
		0x3301 -> time_abs_sync: AbsTime;
		0x3302 -> time_abs_unsync: AbsTime;

	# time delay g52
		0x3401 -> time_coarse: uint16;
		0x3402 -> time_fine: uint16;

	# file control g70
		0x4601 -> file_control_id: File_Control_ID;
		0x4602 -> file_control_auth: File_Control_Auth; # &check(file_control_auth.usr_name_size == 0 && file_control_auth.pwd_size == 0);
		0x4603 -> file_control_cmd: File_Control_Cmd; # &check(file_control_cmd.name_size == 0 && ( file_control_cmd.op_mode == 0 || file_control_cmd.op_mode == 1 || file_control_cmd.op_mode == 2 || file_control_cmd.op_mode == 3) );
		0x4604 -> file_control_cmd_status: File_Control_Cmd_Status(prefix.prefix_value);
		0x4605 -> file_trans: File_Transport(prefix.prefix_value);
		0x4606 -> file_trans_status: File_Transport_Status(prefix.prefix_value);
		#0x4607 -> file_desc: File_Desc_Wrap(function_code);
		0x4607 -> file_desc: File_Desc;

	# internal indication g80
		0x5001 -> iin: uint16;
	# device storage g81
		0x5101 -> dev_store: Dev_Store;

	# device storage g82
		0x5201 -> dev_profile: Dev_Profile;

	# device storage g83
		0x5301 -> priregobj: PrivRegObj;
		0x5302 -> priregobjdesc: PrivRegObjDesc;

	# device storage g85
		0x5501 -> desc_ele: DescEle;

	# data descriptor table g86
		0x5601 -> desc_ele86: DescEle;
		0x5602 -> cha: uint8;
		0x5603 -> point_index_attr: Debug_Byte;

	# Data set g87
		0x5701 -> present_value: Debug_Byte;

	# Data set event g88
		0x5801 -> snapshot: Debug_Byte;

	# status of request operation g91
		0x5b01 -> activate_conf: ActivateConf;

	# bcd value g101
		0x6501 -> bcd_small: uint16;
		0x6502 -> bcd_medium: uint32;
		0x6503 -> bcd_large: BCD_Large;

	# unsigned integer g102
		0x6601 -> unsigned_integer: uint8;

	# authentication challenge g120
		0x7801 -> challenge: AuthChallenge(prefix.prefix_value);
		0x7802 -> reply: AuthReply(prefix.prefix_value);
		0x7803 -> aggrRequest: AuthAggrRequest(prefix.prefix_value);
		0x7804 -> sessionKeyRequest: uint16;
		0x7805 -> status: AuthSessionKeyStatus(prefix.prefix_value);
		0x7806 -> keyChange: AuthSessionKeyChange(prefix.prefix_value);
		0x7807 -> error: AuthError(prefix.prefix_value);
		0x7808 -> user_cert: UserCert(prefix.prefix_value);
		0x7809 -> mac: MAC(prefix.prefix_value);
		0x780A -> user_status_change: UserStatusChange(prefix.prefix_value);
		0x780B -> update_key_req: UpdateKeyReq(prefix.prefix_value);
		0x780C -> update_key_rep: UpdateKeyRep(prefix.prefix_value);
		0x780D -> update_key: UpdateKey(prefix.prefix_value);
		0x780E -> update_key_sig: UpdateKeySig(prefix.prefix_value);
		0x780F -> update_key_con: UpdateKeyCon(prefix.prefix_value);

		#default -> unknowndata: Debug_Byte; # &check( T );
		default -> unmatched: Default_Wrap(object_type_field);
	};
}
  &let{
	data_value: uint8 = case (object_type_field) of {  # this data_value is used for the Zeek Event
		0x0101 -> biwoflag;
		0x0102 -> biwflag;
		0x0a01 -> bowoflag;
		0x0a02 -> bowflag;
		default -> 0xff;
	};
  }
;


######
# this Default_Wrap is created when dealing with g110. Only Group type matters and variations can be all. So too much coding
type Default_Wrap(obj_type: uint32) = record {
	unresolved: case (obj_type & 0xFF00) of {
		0x6E00 -> oct_str: bytestring &length = (obj_type & 0x00FF) ;
		0x6F00 -> oct_str_eve: bytestring &length = (obj_type & 0x00FF) ;
		0x7000 -> vir_ter_out_blk: bytestring &length = (obj_type & 0x00FF) ;
		0x7100 -> vir_ter_eve: bytestring &length = (obj_type & 0x00FF) ;

		#default -> unknown: bytestring &restofdata;
		default -> unknown: Debug_Byte;
	};
};

# contains different objects format
# corresponding to the DNP3Spec-V6-Part2-Objects

# g0: group 0 objects are used to retrieve substation attributes;
# all variations including variation 249 255, share the same structure;
type AttributeCommon = record {
	data_type_code: uint8;
	leng: uint8;
	attribute_obj: bytestring &length=leng;
} &byteorder = littleendian;


# g2v2
type BinInEveAtime = record {
	flag: uint8;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g2v3
type BinInEveRtime = record {
	flag: uint8;
	time16: uint16;
} &byteorder = littleendian;

# g4v2
type DoubleInEveAtime = record {
	flag: uint8;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g4v3
type DoubleInEveRtime = record {
	flag: uint8;
	time16: uint16;
} &byteorder = littleendian;

# g11v2
type BinOutEveAtime = record {
	flag: uint8;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g12v1 group: 12; variation: 1
type CROB = record {
	control_code: uint8; # &check ( (control_code & 0xCF) == 0x00 || (control_code & 0xCF) == 0x01 || (control_code & 0xCF) == 0x03 || (control_code & 0xCF) == 0x04 || (control_code & 0xCF) == 0x41 || (control_code & 0xCF) == 0x81  );
	count: uint8;
	on_time: uint32;
	off_time: uint32;
	status_code: uint8;  # contains the reserved bit
} &byteorder = littleendian;

# g12v2; same as g12v1
type PCB = record {
	control_code: uint8; # &check ( (control_code & 0xCF) == 0x00 || (control_code & 0xCF) == 0x01 || (control_code & 0xCF) == 0x03 || (control_code & 0xCF) == 0x04 || (control_code & 0xCF) == 0x41 || (control_code & 0xCF) == 0x81  );
	count: uint8;
	on_time: uint32;
	off_time: uint32;
	status_code: uint8;  # contains the reserved bit
} &byteorder = littleendian;

# g13v2
type BinOutCmdEveAtime = record {
	flag: uint8;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g20v1; group: 20, variation 1
type Counter32wFlag = record {
	flag: uint8;
	count_value: uint32;
} &byteorder = littleendian;

# g20v2
type Counter16wFlag = record {
	flag: uint8;
	count_value: uint16;
} &byteorder = littleendian;

# g20v3 and g20v4 are obsolete

# g20v5
type Counter32woFlag = record {
	count_value: uint32;
} &byteorder = littleendian;

# g20v6
type Counter16woFlag = record {
	count_value: uint16;
} &byteorder = littleendian;

# g20v7 and g20v8 are obsolete

# g21v1
type FrozenCounter32wFlag = record {
	flag: uint8;
	count_value: uint32;
} &byteorder = littleendian;

# g21v2
type FrozenCounter16wFlag = record {
	flag: uint8;
	count_value: uint16;
} &byteorder = littleendian;

# g21v3 and g21v4 are obsolete

# g21v5
type FrozenCounter32wFlagTime = record {
	flag: uint8;
	count_value: uint32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g21v6
type FrozenCounter16wFlagTime = record {
	flag: uint8;
	count_value: uint16;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g21v7 and g21v8 are obsolete

# g21v9
type FrozenCounter32woFlag = record {
	count_value: uint32;
} &byteorder = littleendian;

# g21v10
type FrozenCounter16woFlag = record {
	count_value: uint16;
} &byteorder = littleendian;

# g21v11 and g21v12 are obsolete

# Conter event g22

# g22v1
type CounterEve32wFlag = record {
	flag: uint8;
	count_value: uint32;
} &byteorder = littleendian;

# g22v2
type CounterEve16wFlag = record {
	flag: uint8;
	count_value: uint16;
} &byteorder = littleendian;

# g22v3 and g22v4 obsolete

# g22v5
type CounterEve32wFlagTime = record {
	flag: uint8;
	count_value: uint32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g22v6
type CounterEve16wFlagTime = record {
	flag: uint8;
	count_value: uint16;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g22v7 g22v8 obsolete

# Conter event g23

# g23v1
type FrozenCounterEve32wFlag = record {
	flag: uint8;
	count_value: uint32;
} &byteorder = littleendian;

# g23v2
type FrozenCounterEve16wFlag = record {
	flag: uint8;
	count_value: uint16;
} &byteorder = littleendian;

# g23v3 and g23v4 obsolete

# g23v5
type FrozenCounterEve32wFlagTime = record {
	flag: uint8;
	count_value: uint32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g23v6
type FrozenCounterEve16wFlagTime = record {
	flag: uint8;
	count_value: uint16;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g23v7 g23v8 obsolete

# group: 30; variation: 1 g30v1
type AnalogInput32wFlag = record {
	flag: uint8;
	value: int32;
} &byteorder = littleendian;

# group: 30; variation: 2
type AnalogInput16wFlag = record {
	flag: uint8;
	value: int16;
} &byteorder = littleendian;

# group: 30; variation: 3
type AnalogInput32woFlag = record {
	value: int32;
} &byteorder = littleendian;

# group: 30; variation: 4
type AnalogInput16woFlag = record {
	value: int16;
} &byteorder = littleendian;

# group: 30; variation: 5; single precision 32 bit
type AnalogInputSPwFlag = record {
	flag: uint8;
	value: uint32;
} &byteorder = littleendian;

# group: 30; variation: 6; double precision 64 bit
type AnalogInputDPwFlag = record {
	flag: uint8;
	value_low: uint32;
	value_high: uint32;
} &byteorder = littleendian;

# g31v1
type FrozenAnalogInput32wFlag = record {
	flag: uint8;
	frozen_value: int32;
} &byteorder = littleendian;

# g31v2
type FrozenAnalogInput16wFlag = record {
	flag: uint8;
	frozen_value: int16;
} &byteorder = littleendian;

# g31v3
type FrozenAnalogInput32wTime = record {
	flag: uint8;
	frozen_value: int32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g31v4
type FrozenAnalogInput16wTime = record {
	flag: uint8;
	frozen_value: int16;
	time48: bytestring &length = 6;
}  &byteorder = littleendian;

# g31v5
type FrozenAnalogInput32woFlag = record {
	frozen_value: int32;
} &byteorder = littleendian;

# g31v6
type FrozenAnalogInput16woFlag = record {
	frozen_value: uint16;
} &byteorder = littleendian;

# g31v7
type FrozenAnalogInputSPwFlag = record {
	flag: uint8;
	frozen_value: uint32;
} &byteorder = littleendian;

# g31v8
type FrozenAnalogInputDPwFlag = record {
	flag: uint8;
	frozen_value_low: uint32;
	frozen_value_high: uint32;
} &byteorder = littleendian;

# group: 32; variation: 1 g32v1
type AnalogInput32woTime = record {
	flag: uint8;
	value: int32;
} &byteorder = littleendian;

# group: 32; variation: 2
type AnalogInput16woTime = record {
	flag: uint8;
	value: int16;
} &byteorder = littleendian;

# group: 32; variation: 3
type AnalogInput32wTime = record {
	flag: uint8;
	value: int32;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 4
type AnalogInput16wTime = record {
	flag: uint8;
	value: int16;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 5; single precision 32 bit
type AnalogInputSPwoTime = record {
	flag: uint8;
	value: uint32;
} &byteorder = littleendian;

# group: 32; variation: 6; double precision 64 bit
type AnalogInputDPwoTime = record {
	flag: uint8;
	value_low: uint32;
	value_high: uint32;
} &byteorder = littleendian;

# group: 32; variation: 7
type AnalogInputSPwTime = record {
	flag: uint8;
	value: uint32;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 8
type AnalogInputDPwTime = record {
	flag: uint8;
	value_low: uint32;
	value_high: uint32;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g33v1
type FrozenAnaInputEve32woTime = record {
	flag: uint8;
	f_value: int32;
} &byteorder = littleendian;

# g33v2
type FrozenAnaInputEve16woTime = record {
	flag: uint8;
	f_value: int16;
} &byteorder = littleendian;

# g33v3
type FrozenAnaInputEve32wTime = record {
	flag: uint8;
	f_value: int32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g33v4
type FrozenAnaInputEve16wTime = record {
	flag: uint8;
	f_value: int32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g33v5
type FrozenAnaInputEveSPwoTime = record {
	flag: uint8;
	f_value: uint32;
} &byteorder = littleendian;

# g33v6
type FrozenAnaInputEveDPwoTime = record {
	flag: uint8;
	f_value_low: uint32;
	f_value_high: uint32;
} &byteorder = littleendian;

# g33v7
type FrozenAnaInputEveSPwTime = record {
	flag: uint8;
	f_value: uint32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g33v8
type FrozenAnaInputEveDPwTime = record {
	flag: uint8;
	f_value_low: uint32;
	f_value_high: uint32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# analog output status g40

# g40v1
type AnaOutStatus32 = record {
	flag: uint8;
	status: int32;
} &byteorder = littleendian;

# g40v2
type AnaOutStatus16 = record {
	flag: uint8;
	status: int16;
} &byteorder = littleendian;

# g40v3
type AnaOutStatusSP = record {
	flag: uint8;
	status: uint32;
} &byteorder = littleendian;

# g40v4
type AnaOutStatusDP = record {
	flag: uint8;
	status_low: uint32;
	status_high: uint32;
} &byteorder = littleendian;

# analog output g41

# g41v1
type AnaOut32 = record {
	value: int32;
	con_status: uint8;
} &byteorder = littleendian;

# g41v2
type AnaOut16 = record {
	value: int16;
	con_status: uint8;
} &byteorder = littleendian;

# g41v3
type AnaOutSP = record {
	value: uint32;
	con_status: uint8;
} &byteorder = littleendian;

# g41v4
type AnaOutDP = record {
	value_low: uint32;
	value_high: uint32;
	con_status: uint8;
} &byteorder = littleendian;

# analog output event g42

# g42v1
type AnaOutEve32woTime = record {
	flag: uint8;
	value: int32;
} &byteorder = littleendian;

# g42v2
type AnaOutEve16woTime = record {
	flag: uint8;
	value: int16;
} &byteorder = littleendian;

# g42v3
type AnaOutEve32wTime = record {
	flag: uint8;
	value: int32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g42v4
type AnaOutEve16wTime = record {
	flag: uint8;
	value: int16;
	time48: bytestring &length = 6;
} &byteorder = littleendian;
# g42v5
type AnaOutEveSPwoTime = record {
	flag: uint8;
	value: uint32;
} &byteorder = littleendian;

# g42v6
type AnaOutEveDPwoTime = record {
	flag: uint8;
	value_low: uint32;
	value_high: uint32;
} &byteorder = littleendian;

# g42v7
type AnaOutEveSPwTime = record {
	flag: uint8;
	value: uint32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g42v8
type AnaOutEveDPwTime = record {
	flag: uint8;
	value_low: uint32;
	value_high: uint32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;

## g43 data format is exactly same as g42 so use g42 directly

# g50v1
type AbsTime = record {
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g50v2
type AbsTimeInterval = record {
	time48: bytestring &length = 6;
	interval: uint32;
} &byteorder = littleendian;

# g50v3
type Last_AbsTime = record {
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# g51v1 and g51v2 are the same structure of g50v1. so reuse it

# g70v1
type Record_Obj = record {
	record_size: uint16;
	record_oct: bytestring &length = record_size;
} &byteorder = littleendian;

type File_Control_ID = record {
	name_size: uint16;
	type_code: uint8;
	attr_code: uint8;
	start_rec: uint16;
	end_rec: uint16;
	file_size: uint32;
	time_create: bytestring &length = 6;
	permission: uint16; # &check ( (permission & 0xFE00 ) == 0x0000);
	file_id: uint32;
	owner_id: uint32;
	group_id: uint32;
	function_code: uint8;
	status_code: uint8;
	file_name: bytestring &length = name_size;
	records: Record_Obj[];
} &byteorder = littleendian;

# g70v2
type File_Control_Auth_Wrap(fc: uint8) = record {
	data: case(fc) of {
		AUTHENTICATE_FILE -> auth_file: File_Control_Auth; # &check(auth_file.auth_key == 0) ;
		default -> null: empty;
	};
};

type File_Control_Auth = record {
	usr_name_offset: uint16;
	usr_name_size: uint16;
	pwd_offset: uint16;
	pwd_size: uint16;
	auth_key: uint32;
	usr_name: bytestring &length = usr_name_size;
	pwd: bytestring &length = pwd_size;
} &byteorder = littleendian;

# g70v3
type File_Control_Cmd_Wrap(function_code: uint8) = record {
	data_obj: case (function_code) of {
		OPEN_FILE -> fc_cmd_open: File_Control_Cmd;
		DELETE_FILE -> fc_cmd_del: File_Control_Cmd; # &check( fc_cmd_del.op_mode == 0 &&  fc_cmd_del.name_size == 0 && fc_cmd_del.time_create == 0x0);
		default -> null: empty;
	};

};

type File_Control_Cmd = record {
	name_offset: uint16;
	name_size: uint16;
	time_create: bytestring &length = 6;
	permission: uint16; # &check ( (permission & 0xFE00 ) == 0x0000);
	auth_key: uint32;
	file_size: uint32;
	op_mode: uint16;
	max_block_size: uint16;
	req_id: uint16;
	file_name: bytestring &length = name_size;
} &byteorder = littleendian;

# g70v4
type File_Control_Cmd_Status_Wrap(function_code: uint8, obj_size: uint32) = record {
	data_obj: case (function_code) of {
		ABORT_FILE -> abort: File_Control_Cmd_Status(obj_size); # &check(abort.file_size == 0 && abort.max_block_size ==0 && abort.status_code ==0 );
		RESPONSE -> fc_cmd_status: File_Control_Cmd_Status(obj_size);
		default -> null: empty;
	};
};

type File_Control_Cmd_Status(obj_size: uint32) = record {
	file_handle: uint32;
	file_size: uint32;
	max_block_size: uint16;
	req_id: uint16 ;
	status_code: uint8;
	#opt_text: bytestring &restofdata;
	opt_text: bytestring &length = (obj_size - 8 - 4 - 1);
} &byteorder = littleendian;

# g70v5
type File_Transport(obj_size: uint32) = record {
	file_handle: uint32;
	block_num: uint32;
	# file_data: bytestring &restofdata;
	file_data: bytestring &length = (obj_size - 8);
} &byteorder = littleendian;

# g70v6
type File_Transport_Status(obj_size: uint32) = record {
	file_handle: uint32;
	block_num: uint32;
	status: uint8;
	#file_data: bytestring &restofdata;
	opt_text: bytestring &length = (obj_size - 4 - 4 - 1);
} &byteorder = littleendian;

# g70v7
type File_Desc_Wrap(function_code: uint8) = record {
	data: case(function_code) of {
		GET_FILE_INFO -> get_file_info: File_Desc; # &check(get_file_info.type ==0 && get_file_info.f_size == 0 && get_file_info.time_create_low == 0 && get_file_info.time_create_high == 0 && get_file_info.permission == 0);
		default -> null: empty;
	};
} &byteorder = littleendian;

type File_Desc = record {
	name_offset: uint16;
	name_size: uint16;
	type: uint16;
	f_size: uint32;
	time_create_low: uint32;
	time_create_high: uint16;
	permission: uint16; # &check ( (permission & 0xFE00 ) == 0x0000);
	req_id: uint16;
	f_name: bytestring &length = name_size;
} &byteorder = littleendian;

# g70v8
type File_Spec_Str = record {
	f_spec: bytestring &restofdata;
} &byteorder = littleendian;

# device storage g81
# g81v1
type Dev_Store = record {
	overflow: uint8;
	obj_group: uint8;
	variation: uint8;
} &byteorder = littleendian;

# device profile g82
# g82v1
type Dev_Profile = record {
	fc_support_low: uint32;
	fc_support_high: uint32;
	count: uint16;
	dev_headers: Dev_Profile_OH[count];
} &byteorder = littleendian;

type Dev_Profile_OH = record {
	group: uint8;
	variation: uint8;
	qualifier: uint8;
	range: uint8;
} &byteorder = littleendian;

# data set g983

# g83v1
type PrivRegObj = record {
	vendor: uint32;
	obj_id: uint16;
	len: uint16;
	data_objs: bytestring &length = len;
} &byteorder = littleendian;

# g83v2
type PrivRegObjDesc = record {
	vendor: uint32;
	obj_id: uint16;
	count: uint16;
	data_objs: ObjDescSpec[count];
} &byteorder = littleendian;

type ObjDescSpec = record {
	obj_quantity: uint16;
	obj_group: uint8;
	obj_variation: uint8;
} &byteorder = littleendian;

# data set prototype g85

# g85v1 only one descriptor element is defined. number of n is defined by number-of-item
type DescEle = record {
	len: uint8;
	desc_code: uint8;
	data_type: uint8;
	max_len: uint8;
	ancillary: uint8;
} &byteorder = littleendian;

# data descriptor element g86

# g86v1 is the same structure of DescEle

# g86v3 does not quite understand specification description

# g87 doest not quite understand specification description

# g88 doest not quite understand specification description

# g90v1
type App_Id(qualifier_field: uint8, object_size16: uint16) = record {
	app_id: case (qualifier_field) of {
		0x5B -> app_name: bytestring &length = object_size16;
		0x06 -> all_app: empty;
		default -> illegal: empty;
	};
} &byteorder = littleendian;

# status of request operation g91
type ActivateConf = record {
	time_delay: uint32;
	count: uint8;
	elements: StatusEle[count];
} &byteorder = littleendian;

type StatusEle = record {
	len: uint8;
	status_code: uint8;
	ancillary: bytestring &length = ( len - 1 );
} &byteorder = littleendian;

# BCD values

# g101v3
type BCD_Large = record {
	value_low: uint32;
	value_high: uint32;
} &byteorder = littleendian;

# authentication g120

# g120v1
type AuthChallenge(prefix: uint16) = record {
	cha_seq_num: uint32;
	user_num: uint16;
	mac_alg: uint8;
	reason: uint8;
	chan_data: bytestring &length = (prefix - 8);
} &byteorder = littleendian;

# g120v2
type AuthReply(prefix: uint16) = record {
	cha_seq_num: uint32;
	user_num : uint16;
	mac: bytestring &length = (prefix - 6);
} &byteorder = littleendian;

# g120v3
type AuthAggrRequest(prefix: uint16) = record {
	cha_seq_num: uint32;
	user_num: uint16;
} &byteorder = littleendian;

# g120v5
type AuthSessionKeyStatus(prefix: uint16) = record {
	cha_seq_num: uint32;
	user_num: uint16;
	key_alg: uint8;
	key_status: uint8;
	mac_alg: uint8;
	cha_data_len : uint16;
	chan_data: bytestring &length = cha_data_len;
	mac: bytestring &length = (prefix - 11 - cha_data_len);
} &byteorder = littleendian;

# g120v6
type AuthSessionKeyChange(prefix: uint16) = record {
	key_change_num: uint32;
	user_num: uint16;
	key_wrap_data: bytestring &length = (prefix - 6);
} &byteorder = littleendian;

# g120v7
type AuthError(prefix: uint16) = record {
	cha_seq_num: uint32;
	user_num: uint16;
	id: uint16;
	error_code: uint8;
	time_error: bytestring &length = 6;
	error_text: bytestring &length = (prefix - 15);
} &byteorder = littleendian;

# g120v8
type UserCert(prefix: uint16) = record {
	method: uint8;
	cert_type: uint8;
	cert_text: bytestring &length = (prefix - 2);
} &byteorder = littleendian;

# g120v9
type MAC(prefix: uint16) = record {
	mac_text: bytestring &length = prefix;
} &byteorder = littleendian;

# g120v10
type UserStatusChange(prefix: uint16) = record {
	method: uint8;
	operation: uint8;
	seq_num: uint32;
	user_role: uint16;
	user_role_exp: uint16;
	user_name_len: uint16;
	user_pubkey_len: uint16;
	cert_data_len: uint16;
	user_name: bytestring &length = user_name_len;
	user_pubkey: bytestring &length = user_pubkey_len;
	cert_data: bytestring &length = cert_data_len;
} &byteorder = littleendian;

# g120v11
type UpdateKeyReq(prefix: uint16) = record {
	method: uint8;
	user_name_len: uint16;
	master_cha_data_len: uint16;
	user_name: bytestring &length = user_name_len;
	master_cha_data: bytestring &length = master_cha_data_len;
} &byteorder = littleendian;

# g120v12
type UpdateKeyRep(prefix: uint16) = record {
	seq_num: uint32;
	user_num: uint16;
	user_name_len: uint16;
	outstation_cha_data_len: uint16;
	outstation_cha_data: bytestring &length = outstation_cha_data_len;
} &byteorder = littleendian;

# g120v13
type UpdateKey(prefix: uint16) = record {
	seq_num: uint32;
	user_num: uint16;
	update_key_len: uint16;
	update_key_data: bytestring &length = update_key_len;
} &byteorder = littleendian;

# g120v14
type UpdateKeySig(prefix: uint16) = record {
	digital_sig: bytestring &length = prefix;
} &byteorder = littleendian;

# g120v15
type UpdateKeyCon(prefix: uint16) = record {
	mac: bytestring &length = prefix;
} &byteorder = littleendian;
