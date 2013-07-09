type Syslog_Message = record {
	PRI: Syslog_Priority;
	msg: bytestring &restofdata;
} &byteorder = littleendian;

type Syslog_Priority = record {
	lt    : uint8 &check(lt == "<");
	val   : RE/[[:digit:]]+/;
	gt    : uint8 &check(gt == ">");
} &let {
	val_length: int = sizeof(val) - 1;
	int_val: int = bytestring_to_int(val, 10);
	severity: int = (int_val & 0x07);
	facility: int = (int_val & 0x03f8) >> 3;
};
