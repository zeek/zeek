# contains different objects format
# corresponding to the DNP3Spec-V6-Part2-Objects 

# g12v1 group: 12; variation: 1
type CROB = record{
	control_code: uint8 &check ( (control_code & 0xCF) == 0x00 || (control_code & 0xCF) == 0x01 || (control_code & 0xCF) == 0x03 || (control_code & 0xCF) == 0x04 || 
					(control_code & 0xCF) == 0x41 || (control_code & 0xCF) == 0x81  );
	count: uint8;
	on_time: uint32;
	off_time: uint32;
	status_code: uint8;  # contains the reserved bit
} &byteorder = littleendian;
# g12v2; same as g12v1
type PCB = record{
	control_code: uint8 &check ( (control_code & 0xCF) == 0x00 || (control_code & 0xCF) == 0x01 || (control_code & 0xCF) == 0x03 || (control_code & 0xCF) == 0x04 || 
					(control_code & 0xCF) == 0x41 || (control_code & 0xCF) == 0x81  );
	count: uint8;
	on_time: uint32;
	off_time: uint32;
	status_code: uint8;  # contains the reserved bit
} &byteorder = littleendian;

# g20v1; group: 20, variation 1
type Counter32wFlag = record{
	flag: uint8;
	count_value: uint32;
} &byteorder = littleendian;
# g20v2
type Counter16wFlag = record{
	flag: uint8;
	count_value: uint16;
} &byteorder = littleendian;
# g20v3 and g20v4 are obsolete
# g20v5
type Counter32woFlag = record{
	count_value: uint32;
} &byteorder = littleendian;
# g20v6
type Counter16woFlag = record{
	count_value: uint16;
} &byteorder = littleendian;
# g20v7 and g20v8 are obsolete

# g21v1
type FrozenCounter32wFlag = record{
	flag: uint8;
	count_value: uint32;
} &byteorder = littleendian;
# g21v2
type FrozenCounter16wFlag = record{
	flag: uint8;
	count_value: uint16;
} &byteorder = littleendian;
# g21v3 and g21v4 are obsolete
# g21v5
type FrozenCounter32wFlagTime = record{
	flag: uint8;
	count_value: uint32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;
# g21v6
type FrozenCounter16wFlagTime = record{
	flag: uint8;
	count_value: uint16;
	time48: bytestring &length = 6;
} &byteorder = littleendian;
# g21v7 and g21v8 are obsolete
# g21v9
type FrozenCounter32woFlag = record{
        count_value: uint32;
} &byteorder = littleendian;
# g21v10
type FrozenCounter16woFlag = record{
        count_value: uint16;
} &byteorder = littleendian;
# g21v11 and g21v12 are obsolete


# group: 30; variation: 1
type AnalogInput32wFlag = record{
        flag: uint8;
        value: int32;
} &byteorder = littleendian;

# group: 30; variation: 2
type AnalogInput16wFlag = record{
        flag: uint8;
        value: int16;
} &byteorder = littleendian;

# group: 30; variation: 3
type AnalogInput32woFlag = record{
        value: int32;
} &byteorder = littleendian;

# group: 30; variation: 4
type AnalogInput16woFlag = record{
        value: int16;
} &byteorder = littleendian;

# group: 30; variation: 5; singple precision 32 bit
type AnalogInputSPwFlag = record{
        flag: uint8;
        value: uint32;
} &byteorder = littleendian;

# group: 30; variation: 6; double precision 64 bit
type AnalogInputDPwFlag = record{
        flag: uint8;
        value_low: uint32;
	value_high: uint32;
} &byteorder = littleendian;

# g31v1
type FrozenAnalogInput32wFlag = record{
        flag: uint8;
        frozen_value: int32;
} &byteorder = littleendian;
# g31v2
type FrozenAnalogInput16wFlag = record{
        flag: uint8;
        frozen_value: int16;
} &byteorder = littleendian;
# g31v3
type FrozenAnalogInput32wTime = record{
	flag: uint8;
        frozen_value: int32;
	time48: bytestring &length = 6;
} &byteorder = littleendian;
# g31v4
type FrozenAnalogInput16wTime = record{
        flag: uint8;
	frozen_value: int16;
	time48: bytestring &length = 6;
}  &byteorder = littleendian;
# g31v5
type FrozenAnalogInput32woFlag = record{
        frozen_value: int32;
} &byteorder = littleendian;
# g31v6
type FrozenAnalogInput16woFlag = record{
        frozen_value: uint16;
} &byteorder = littleendian;
# g31v7
type FrozenAnalogInputSPwFlag = record{
        flag: uint8;
        frozen_value: uint32;
} &byteorder = littleendian;
# g31v8
type FrozenAnalogInputDPwFlag = record{
        flag: uint8;
        value_low: uint32;
        value_high: uint32;
} &byteorder = littleendian;

# group: 32; variation: 1
type AnalogInput32woTime = record{
	flag: uint8;
	value: uint32;
} &byteorder = littleendian;

# group: 32; variation: 2
type AnalogInput16woTime = record{
	flag: uint8;
	value: uint16;
} &byteorder = littleendian;

# group: 32; variation: 3
type AnalogInput32wTime = record{
	flag: uint8;
	value: uint32;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 4
type AnalogInput16wTime = record{
	flag: uint8;
	value: uint16;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 5; singple precision 32 bit
type AnalogInputSPwoTime = record{
	flag: uint8;
	value: uint32;
} &byteorder = littleendian;

# group: 32; variation: 6; double precision 64 bit
type AnalogInputDPwoTime = record{
	flag: uint8;
	value_low: uint32;
	value_high: uint32;
} &byteorder = littleendian;

# group: 32; variation: 7
type AnalogInputSPwTime = record{
	flag: uint8;
	value: uint32;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 8
type AnalogInputDPwTime = record{
	flag: uint8;
	value_low: uint32;
	value_high: uint32;
	#time: uint8[6];
	time48: bytestring &length = 6;
} &byteorder = littleendian;

