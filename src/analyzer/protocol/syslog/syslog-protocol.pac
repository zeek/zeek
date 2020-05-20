type Syslog_Message_Optional_PRI = record {
	lt:       uint8;
	after_lt: bytestring &restofdata &transient;
}
&byteorder = littleendian
&exportsourcedata
&let {
	standard:    Syslog_Message(true) withinput sourcedata &if(lt == 60); # '<'
	nonstandard: Syslog_Message(false) withinput sourcedata &if(lt != 60);
};

type Syslog_Message(has_pri: bool) = record {
	opt_pri: case has_pri of {
		true  -> PRI: Syslog_Priority;
		false -> nothing: empty;
	};

	msg: bytestring &restofdata;
} &byteorder = littleendian;

type Syslog_Priority = record {
	lt    : uint8 &enforce(lt == 60); # '<'
	val   : RE/[[:digit:]]+/;
	gt    : uint8 &enforce(gt == 62); # '>'
} &let {
	val_length: int = sizeof(val) - 1;
	int_val: int = bytestring_to_int(val, 10);
	severity: int = (int_val & 0x07);
	facility: int = (int_val & 0x03f8) >> 3;
};
