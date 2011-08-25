# $Id:$
#
# This template code contributed by Kristin Stephens.

#type START_TOKEN = 0x6405;

type Dnp3TCP_PDU = record {
	header: Header_Block;
	blocks: Data_Block[ (header.len - 5) / 16 ];
	rest: bytestring &restofdata;
	
} &byteorder = bigendian 
  &length= 10 + header.len -5 + (((header.len - 5)/16) + 1)*2
;

type Header_Block = record {
	start: uint16 &check(start == 0x0564);
	len: uint8;
	ctrl: uint8;
	dest_addr: uint16;
	src_addr: uint16;
	crc: uint16; 
} &byteorder = littleendian 
&length = 10;

type Data_Block = record {
	#data: uint8[16];  // don't know how to pass array between event.bif binpac and bro
	#data1: uint32;
	#data2: uint32;
	#data3: uint32;
	#data4: uint32;
	data: bytestring &length = 16;
	crc: uint16;
} &length = 18;
