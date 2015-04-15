# Basic PE types

type Mem_Info32 = record {
	size_of_stack_reserve : uint32;
	size_of_stack_commit  : uint32;
	size_of_heap_reserve  : uint32;
	size_of_heap_commit   : uint32;
} &byteorder=littleendian &length=16;

type Mem_Info64 = record {
	size_of_stack_reserve : uint64;
	size_of_stack_commit  : uint64;
	size_of_heap_reserve  : uint64;
	size_of_heap_commit   : uint64;
} &byteorder=littleendian &length=32;

type RVAS(num: uint32) = record {
	rvas : RVA[num];
};

type RVA = record {
	virtual_address : uint32;
	size		: uint32;
} &length=8;

# The BinPAC padding type doesn't work here.
type Padding(length: uint32) = record {
	pad: bytestring &length=length &transient;
};

type null_terminated_string = RE/[A-Za-z0-9.]+\x00/;

