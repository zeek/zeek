# contains different objects format
# corresponding to the DNP3Spec-V6-Part2-Objects 

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
	time: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 4
type AnalogInput16wTime = record{
	flag: uint8;
	value: uint16;
	#time: uint8[6];
	time: bytestring &length = 6;
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
	time: bytestring &length = 6;
} &byteorder = littleendian;

# group: 32; variation: 8
type AnalogInputDPwTime = record{
	flag: uint8;
	value_low: uint32;
	value_high: uint32;
	#time: uint8[6];
	timt: bytestring &length = 6;
} &byteorder = littleendian;

# group: 30; variation: 1
type AnalogInput32wFlag = record{
        flag: uint8;
        value: uint32;
} &byteorder = littleendian;

# group: 30; variation: 2
type AnalogInput16wFlag = record{
        flag: uint8;
        value: uint16;
} &byteorder = littleendian;

# group: 30; variation: 3
type AnalogInput32woFlag = record{
        value: uint32;
} &byteorder = littleendian;

# group: 30; variation: 4
type AnalogInput16woFlag = record{
        value: uint16;
}
  &byteorder = littleendian
;

# group: 30; variation: 5; singple precision 32 bit
type AnalogInputSPwFlag = record{
        flag: uint8;
        value: uint32;
} &byteorder = littleendian;
# group: 30; variation: 6; double precision 64 bit
type AnalogInputDPwFlag = record{
        flag: uint8;
        value: uint32[2];
} &byteorder = littleendian;
