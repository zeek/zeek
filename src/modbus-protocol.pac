#Copyright (c) 2011 SecurityMatters BV. All rights reserved.

##Redistribution and use in source and binary forms, with or without
##modification, are permitted provided that the following conditions are met:

##(1) Redistributions of source code must retain the above copyright notice,
##    this list of conditions and the following disclaimer.

##(2) Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.

##(3) Neither the name of SecurityMatters BV, nor the names of contributors 
##	may be used to endorse or promote products derived from this software 
##	without specific prior written permission.

##THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
##AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
##IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
##ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
##LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
##CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
##SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
##INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
##CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
##ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
##POSSIBILITY OF SUCH DAMAGE.


##
## Modbus/TCP protocol
## Based on OPEN MODBUS/TCP SPECIFICATION
## Release 1.0, 29 March 1999
##

analyzer ModbusTCP withcontext {
    connection: 		ModbusTCP_Conn;
    flow:       		ModbusTCP_Flow;
};

connection ModbusTCP_Conn( bro_analyzer: BroAnalyzer) {
    upflow = ModbusTCP_Flow(true);
    downflow = ModbusTCP_Flow(false);
};

enum function_codes {
# Class 0
	READ_MULTIPLE_REGISTERS = 3,
	WRITE_MULTIPLE_REGISTERS = 16,
# Class 1
	READ_COILS = 1,
	READ_INPUT_DISCRETES = 2,
	READ_INPUT_REGISTERS = 4,
	WRITE_COIL = 5,
	WRITE_SINGLE_REGISTER = 6,
	READ_EXCEPTION_STATUS = 7,
# Class 2
	FORCE_MULTIPLE_COILS = 15,
	READ_GENERAL_REFERENCE = 20,
	WRITE_GENERAL_REFERENCE = 21,
	MASK_WRITE_REGISTER = 22,
	READ_WRITE_REGISTERS = 23,
	READ_FIFO_QUEUE = 24,
# Machine/vendor/network specific functions
	DIAGNOSTICS = 8,
	PROGRAM_484 = 9,
	POLL_484 = 10,
	GET_COMM_EVENT_COUNTERS = 11,
	GET_COMM_EVENT_LOG = 12,
	PROGRAM_584_984 = 13,
	POLL_584_984 = 14,
	REPORT_SLAVE = 17,
	PROGRAM_884_U84 = 18,
	RESET_COMM_LINK_884_U84 = 19,
	PROGRAM_CONCEPT = 40,
	FIRMWARE_REPLACEMENT = 125,
	PROGRAM_584_984_2 = 126,
	REPORT_LOCAL_ADDRESS = 127,
# Exceptions
	READ_MULTIPLE_REGISTERS_EXCEPTION = 0x83,
	WRITE_MULTIPLE_REGISTERS_EXCEPTION = 0x90,
	READ_COILS_EXCEPTION = 0x81,
	READ_INPUT_DISCRETES_EXCEPTION = 0x82,
	READ_INPUT_REGISTERS_EXCEPTION = 0x84,
	WRITE_COIL_EXCEPTION = 0x85,
	WRITE_SINGLE_REGISTER_EXCEPTION = 0x86,
	READ_EXCEPTION_STATUS_EXCEPTION = 0x87,
	FORCE_MULTIPLE_COILS_EXCEPTION = 0x8F,
	READ_GENERAL_REFERENCE_EXCEPTION = 0x94,
	WRITE_GENERAL_REFERENCE_EXCEPTION = 0x95,
	MASK_WRITE_REGISTER_EXCEPTION = 0x96,
	READ_WRITE_REGISTERS_EXCEPTION = 0x97,
	READ_FIFO_QUEUE_EXCEPTION = 0x98,
};

#
# Main Modbus/TCP PDU
#
type ModbusTCP_PDU(is_orig: bool) = case is_orig of {
	true  -> request:  ModbusTCP_RequestPDU;
	false -> response: ModbusTCP_ResponsePDU;
} &byteorder=bigendian;

type ModbusTCP_TransportHeader = record {
	tid: uint16;				# Transaction identifier
	pid: uint16;				# Protocol identifier
	len: uint16; 				# Length of everyting after this field
	uid: uint8;					# Unit identifier (previously 'slave address')
	fc: uint8 ; 					# MODBUS function code (see function_codes enum) 

};



type Reference (header:ModbusTCP_TransportHeader) = record {
	refType: uint8;
	refNumber: uint32;
	wordCount: uint16;
}
&let {
deliver: bool =$context.flow.deliver_ReadSingleReferenceReq(header.tid,header.pid,header.uid,header.fc,refType,refNumber,wordCount);
};


type ReferenceWithData (header:ModbusTCP_TransportHeader) = record {
	refType: uint8;
	refNumber: uint32;
	wordCount: uint16;
	registerValue: uint16[wordCount] &length = 2*wordCount; # TODO: check that the array length is calculated correctly
}
&let {
deliver: bool =$context.flow.deliver_WriteSingleReference(header.tid,header.pid,header.uid,header.fc,refType,refNumber,wordCount,this);
}

;

#Dina modified
type ReferenceResponse(header:ModbusTCP_TransportHeader)=record{
	byteCount:uint8;
	refType:uint8;
	registerValue:uint16[wordCount];
}
	&let  {
		wordCount : uint8 = byteCount/2;

		deliver: bool =$context.flow.deliver_ReadSingleReferenceRes(header.tid,header.pid,header.uid,header.fc,byteCount,refType,this);

};


type Exception(len: uint16,header:ModbusTCP_TransportHeader) = record {
	code: uint8;
}&let {
deliver: bool =$context.flow.deliver_Exception(header.tid,header.pid,header.uid,header.fc,code);
};


type ModbusTCP_RequestPDU = record {
    header: ModbusTCP_TransportHeader;
    data: case header.fc of {
    	# Class 0
		READ_MULTIPLE_REGISTERS -> readMultipleRegisters: ReadMultipleRegistersRequest(header.len-2,header);
		WRITE_MULTIPLE_REGISTERS -> writeMultipleRegisters: WriteMultipleRegistersRequest(header.len-2,header);
		# Class 1
		READ_COILS -> readCoils: ReadCoilsRequest(header.len-2,header);
		READ_INPUT_DISCRETES -> readInputDiscretes: ReadInputDiscretesRequest(header.len-2,header);
		READ_INPUT_REGISTERS -> readInputRegisters: ReadInputRegistersRequest(header.len-2,header);
		WRITE_COIL -> writeCoil: WriteCoilRequest(header.len-2,header);
		WRITE_SINGLE_REGISTER -> writeSingleRegister: WriteSingleRegisterRequest(header.len-2,header);
		READ_EXCEPTION_STATUS -> readExceptionStatus: ReadExceptionStatusRequest(header.len-2,header);
		# Class 2
		FORCE_MULTIPLE_COILS -> forceMultipleCoils: ForceMultipleCoilsRequest(header.len-2,header);
		READ_GENERAL_REFERENCE -> readGeneralreference: ReadGeneralReferenceRequest(header.len-2,header);
		WRITE_GENERAL_REFERENCE -> writeGeneralReference: WriteGeneralReferenceRequest(header.len-2,header);
		MASK_WRITE_REGISTER -> maskWriteRegister: MaskWriteRegisterRequest(header.len-2,header);
		READ_WRITE_REGISTERS -> readWriteRegisters: ReadWriteRegistersRequest(header.len-2,header);
		READ_FIFO_QUEUE -> readFIFOQueue: ReadFIFOQueueRequest(header.len-2,header);
		# All the rest
		default -> unknown: bytestring &restofdata;
};	
} &length = (header.len+6) &let {
   deliver: bool =$context.flow.deliver_message(header.tid, header.pid,header.uid, header.fc ,1); #1 is flag for request
	
};

# Class 0 requests


#REQUEST FC=3
type ReadMultipleRegistersRequest(len: uint16,header: ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	wordCount: uint16 &check(wordCount <= 125);
} 
  &let {
deliver: bool =$context.flow.deliver_ReadMultiRegReq(header.tid,header.pid,header.uid,header.fc,referenceNumber,wordCount,1,len);
};


#REQUEST FC=16

type WriteMultipleRegistersRequest(len: uint16, header: ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	wordCount: uint16 &check(wordCount <= 100);
	byteCount: uint8;
	registers: uint16[wordCount] &length = byteCount;
} &let {
	deliver: bool =$context.flow.deliver_WriteMultiRegReq(this,header.tid,header.pid,header.uid,header.fc,len);
};

# Class 1 requests


#REQUEST FC=1
type ReadCoilsRequest(len: uint16,header:ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	bitCount: uint16 &check(bitCount <= 2000);
} &let 
{
deliver: bool =$context.flow.deliver_ReadCoilsReq(header.tid,header.pid,header.uid,header.fc,referenceNumber,bitCount);
	};


#REQUEST FC=2
type ReadInputDiscretesRequest(len: uint16,header:ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	bitCount: uint16 &check(bitCount <= 2000);
}
&let
{
deliver: bool =$context.flow.deliver_ReadInputDiscReq(header.tid,header.pid,header.uid,header.fc,referenceNumber,bitCount);
        };

#REQUEST FC=4

type ReadInputRegistersRequest(len: uint16,header: ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	wordCount: uint16 &check(wordCount <= 125);
}
&let {
deliver: bool =$context.flow.deliver_ReadInputRegReq(header.tid,header.pid,header.uid,header.fc,referenceNumber,wordCount,1,len);
};



#REQUEST FC=5
type WriteCoilRequest(len: uint16,header:ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	onOff: uint8 &check(onOff == 0x00 || onOff == 0xFF);
	other: uint8 &check(other == 0x00);
}
&let {
deliver: bool =$context.flow.deliver_WriteCoilReq(header.tid,header.pid,header.uid,header.fc,referenceNumber,onOff,other);

};



#REQUEST FC=6
type WriteSingleRegisterRequest(len: uint16, header:ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	registerValue: uint16;

}
 &let {
deliver: bool =$context.flow.deliver_WriteSingleRegReq(header.tid,header.pid,header.uid,header.fc,len,referenceNumber,registerValue);
};



type ReadExceptionStatusRequest(len:uint16,header:ModbusTCP_TransportHeader) = record {
} &let {

deliver: bool =$context.flow.deliver_ReadExceptStatReq(header.tid,header.pid,header.uid,header.fc,len);
};

# Class 2 requests

#REQUEST FC=15
type ForceMultipleCoilsRequest(len: uint16,header:ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	bitCount: uint16 &check(bitCount <= 800);
	byteCount: uint8 &check(byteCount == (bitCount + 7)/8);
	coils: bytestring &length = byteCount;
}
 &let {
deliver: bool =$context.flow.deliver_ForceMultiCoilsReq(header.tid,header.pid,header.uid,header.fc,referenceNumber,bitCount,byteCount,coils);
};

#REQUEST FC=20
type ReadGeneralReferenceRequest(len: uint16,header:ModbusTCP_TransportHeader) = record {
	byteCount: uint8;
	references: Reference(header)[referenceCount] &length = byteCount;
} &let {
	referenceCount: uint8 = byteCount/7;

	deliver: bool =$context.flow.deliver_ReadReferenceReq(header.tid,header.pid,header.uid,header.fc,referenceCount,references);

};


#REQUEST FC=21
type WriteGeneralReferenceRequest(len: uint16,header:ModbusTCP_TransportHeader) = record {
	byteCount: uint8;
	references: ReferenceWithData(header)[] &until($input.length() == 0) &length = byteCount;
} &length = len,
  &let {
        deliver: bool =$context.flow.deliver_WriteReferenceReq(header.tid,header.pid,header.uid,header.fc,byteCount,references);

};


#REQUESTeFC=22
type MaskWriteRegisterRequest(len: uint16,header: ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	andMask: uint16;
	orMask: uint16;
}
&let{
        deliver: bool =$context.flow.deliver_MaskWriteRegReq(header.tid,header.pid,header.uid,header.fc,referenceNumber, andMask, orMask);
};


#REQUEST FC=23

type ReadWriteRegistersRequest(len: uint16,header: ModbusTCP_TransportHeader) = record {
	referenceNumberRead: uint16;
	wordCountRead: uint16 &check(wordCountRead <= 125);
	referenceNumberWrite: uint16;
	wordCountWrite: uint16 &check(wordCountWrite <= 100);
	byteCount: uint8 &check(byteCount == 2*wordCountWrite);
	registerValues: uint16[registerCount] &length = byteCount;
} &length = len, &let{
	registerCount : uint8 = byteCount / 2;
	 deliver: bool =$context.flow.deliver_ReadWriteRegReq(this,header.tid,header.pid,header.uid,header.fc,len);
};

#REQUEST FC=24
type ReadFIFOQueueRequest(len: uint16,header: ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
}
&let{
        deliver: bool =$context.flow.deliver_ReadFIFOReq(header.tid,header.pid,header.uid,header.fc,referenceNumber);
};

#Responses
#
type ModbusTCP_ResponsePDU = record {
    header: ModbusTCP_TransportHeader;
    data:  case header.fc of {
    	# Class 0
    	READ_MULTIPLE_REGISTERS -> readMultipleRegisters: ReadMultipleRegistersResponse(header.len-2, header);
        WRITE_MULTIPLE_REGISTERS -> writeMultipleRegisters: WriteMultipleRegistersResponse(header.len-2,header);
        # Class 1
        READ_COILS -> readCoils: ReadCoilsResponse(header.len-2,header);
        READ_INPUT_DISCRETES -> readInputDiscretes: ReadInputDiscretesResponse(header.len-2,header);
        READ_INPUT_REGISTERS -> readInputRegisters: ReadInputRegistersResponse(header.len-2,header);
        WRITE_COIL -> writeCoil: WriteCoilResponse(header.len-2,header);
        WRITE_SINGLE_REGISTER -> writeSingleRegister: WriteSingleRegisterResponse(header.len-2,header);
        READ_EXCEPTION_STATUS -> readExceptionStatus: ReadExceptionStatusResponse(header.len-2,header);
        FORCE_MULTIPLE_COILS -> forceMultipleCoils: ForceMultipleCoilsResponse(header.len-2,header);
        READ_GENERAL_REFERENCE -> readGeneralReference: ReadGeneralReferenceResponse(header.len-2,header);
        WRITE_GENERAL_REFERENCE -> writeGeneralReference: WriteGeneralReferenceResponse(header.len-2,header);
        MASK_WRITE_REGISTER -> maskWriteRegister: MaskWriteRegisterResponse(header.len-2,header);
        READ_WRITE_REGISTERS -> readWriteRegisters: ReadWriteRegistersResponse(header.len-2,header);
        READ_FIFO_QUEUE -> readFIFOQueue: ReadFIFOQueueResponse(header.len-2,header);
        # Exceptions
        READ_MULTIPLE_REGISTERS_EXCEPTION -> readMultipleRegistersException : Exception(header.len-2,header);
		WRITE_MULTIPLE_REGISTERS_EXCEPTION -> writeMultipleRegistersException: Exception(header.len-2,header);
		READ_COILS_EXCEPTION -> readCoilsException: Exception(header.len-2,header);
		READ_INPUT_DISCRETES_EXCEPTION -> readInputDiscretesException: Exception(header.len-2,header);
		READ_INPUT_REGISTERS_EXCEPTION -> readInputRegistersException: Exception(header.len-2,header);
		WRITE_COIL_EXCEPTION -> writeCoilException: Exception(header.len-2,header);
		WRITE_SINGLE_REGISTER_EXCEPTION -> writeSingleRegisterException: Exception(header.len-2,header);
		READ_EXCEPTION_STATUS_EXCEPTION -> readExceptionStatusException: Exception(header.len-2,header);
		FORCE_MULTIPLE_COILS_EXCEPTION -> forceMultipleCoilsException: Exception(header.len-2,header);
		READ_GENERAL_REFERENCE_EXCEPTION -> readGeneralReferenceException: Exception(header.len-2,header);
		WRITE_GENERAL_REFERENCE_EXCEPTION -> writeGeneralReferenceException: Exception(header.len-2,header);
		MASK_WRITE_REGISTER_EXCEPTION -> maskWriteRegisterException: Exception(header.len-2,header);
		READ_WRITE_REGISTERS_EXCEPTION -> readWriteRegistersException: Exception(header.len-2,header);
		READ_FIFO_QUEUE_EXCEPTION -> readFIFOQueueException: Exception(header.len-2,header);
		# All the rest
        default -> unknown: bytestring &restofdata;
};   
} &length = (header.len+6) &let {
	deliver: bool =$context.flow.deliver_message(header.tid,header.pid,header.uid,header.fc,2); #2 is flag for response
};

# Class 0 responses


###RESPONSE FC=3
type ReadMultipleRegistersResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	byteCount: uint8;
	registers: uint16[registerCount] &length = byteCount;
} &let{
	registerCount : uint8 = byteCount/2;

	deliver: bool =$context.flow.deliver_ReadMultiRegRes(this,header.tid,header.pid,header.uid,header.fc,len);

};


###RESPONSE FC=16
type WriteMultipleRegistersResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	wordCount: uint16;
} &let {
deliver: bool =$context.flow.deliver_WriteMultiRegRes(header.tid,header.pid,header.uid,header.fc,referenceNumber,wordCount,len);

};


# Class 1 responses

###RESPONSE FC=1
type ReadCoilsResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	byteCount: uint8;
	bits: bytestring &length = byteCount;
}&let{
 deliver: bool =$context.flow.deliver_ReadCoilsRes(header.tid,header.pid,header.uid,header.fc,byteCount,bits);
}
;


###RESPONSE FC=2
type ReadInputDiscretesResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	byteCount: uint8;
	bits: bytestring &length = byteCount;
}
&let{
 deliver: bool =$context.flow.deliver_ReadInputDiscRes(header.tid,header.pid,header.uid,header.fc,byteCount,bits);
}

;


###RESPONSE FC=4
type ReadInputRegistersResponse(len: uint16, header:ModbusTCP_TransportHeader) = record {
	byteCount: uint8;
	registers: uint16[registerCount] &length = byteCount;
} &let {
	registerCount = byteCount/2;
	deliver: bool =$context.flow.deliver_ReadInputRegRes(this,header.tid,header.pid,header.uid,header.fc,len);
};

###RESPONSE FC=5
type WriteCoilResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	onOff: uint8 &check(onOff == 0x00 || onOff == 0xFF);
	other: uint8 &check(other == 0x00);
}
&let {
deliver: bool =$context.flow.deliver_WriteCoilRes(header.tid,header.pid,header.uid,header.fc,referenceNumber,onOff,other);

};

###RESPONSE FC=6
type WriteSingleRegisterResponse(len: uint16, header:ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	registerValue: uint16;
}
 &let {
deliver: bool =$context.flow.deliver_WriteSingleRegRes(header.tid,header.pid,header.uid,header.fc,len,referenceNumber,registerValue);

};


type ReadExceptionStatusResponse(len:uint16,header:ModbusTCP_TransportHeader) = record {
	status: uint8;
} &let {

deliver: bool =$context.flow.deliver_ReadExceptStatRes(header.tid,header.pid,header.uid,header.fc,status,len);
};

# Class 2 responses

#RESPONSE FC=15
type ForceMultipleCoilsResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	bitCount: uint16;
}
 &let {

deliver: bool =$context.flow.deliver_ForceMultiCoilsRes(header.tid,header.pid,header.uid,header.fc,referenceNumber,bitCount);
}
;


###RESPONSE FC=20
type ReadGeneralReferenceResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	byteCount: uint8;
	#references: bytestring &length = byteCount;
	#Dina modified
	references:ReferenceResponse (header) [] &until($input.length()==0) &length=byteCount;
} &length = len,
&let{
        deliver: bool =$context.flow.deliver_ReadReferenceRes(header.tid,header.pid,header.uid,header.fc,byteCount,references);
};

###RESPONSE FC=21
type WriteGeneralReferenceResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	byteCount: uint8;
	references: ReferenceWithData(header)[] &until($input.length() == 0) &length = byteCount;
} &length = len,
&let {
        deliver: bool =$context.flow.deliver_WriteReferenceRes(header.tid,header.pid,header.uid,header.fc,byteCount,references);

};



###RESPOeSE FC=22
type MaskWriteRegisterResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	referenceNumber: uint16;
	andMask: uint16;
	orMask: uint16;
}
&let{
        deliver: bool =$context.flow.deliver_MaskWriteRegRes(header.tid,header.pid,header.uid,header.fc,referenceNumber, andMask, orMask);
};



###RESPONSE FC=23
type ReadWriteRegistersResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	byteCount: uint8;
	registerValues: uint16[registerCount] &length = byteCount;
} &length = len, &let {
	registerCount = byteCount / 2;
 deliver: bool =$context.flow.deliver_ReadWriteRegRes(this,header.tid,header.pid,header.uid,header.fc,len);
};



###RESPONSE FC=24
type ReadFIFOQueueResponse(len: uint16,header:ModbusTCP_TransportHeader) = record {
	byteCount: uint16 &check(byteCount <= 64);
	wordCount: uint16 &check(wordCount <= 31);
	registerData: uint16[wordCount] &length = byteCount; 
} &length = len,
&let{
 	deliver: bool =$context.flow.deliver_ReadFIFORes(this,header.tid,header.pid,header.uid,header.fc);
	}

;


#
