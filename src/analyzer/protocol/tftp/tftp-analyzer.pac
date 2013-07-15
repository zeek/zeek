
%extern{
#include "file_analysis/Manager.h"
%}

connection TFTP_Conn(bro_analyzer: BroAnalyzer)
{
	upflow   = TFTP_Flow;
	downflow = TFTP_Flow;
};

flow TFTP_Flow
{
	datagram = TFTP_Message withcontext(connection, this);

	function process_read_request(m: ReadRequest): bool
		%{
		BifEvent::generate_tftp_read_request(connection()->bro_analyzer(),
		                                     connection()->bro_analyzer()->Conn(),
		                                     bytestring_to_val(${m.file.str}),
		                                     bytestring_to_val(${m.type.str}));
		return true;
		%}

	function process_write_request(m: WriteRequest): bool
		%{
		BifEvent::generate_tftp_write_request(connection()->bro_analyzer(),
		                                      connection()->bro_analyzer()->Conn(),
		                                      bytestring_to_val(${m.file.str}),
		                                      bytestring_to_val(${m.type.str}));
		return true;
		%}

	function process_datachunk(m: DataChunk): bool
		%{
		file_mgr->DataIn(${m.data}.begin(), 
		                 ${m.data}.length(),
		                 (uint64) ${m.block}*512,
		                 connection()->bro_analyzer()->GetAnalyzerTag(), 
		                 connection()->bro_analyzer()->Conn(),
		                 true);
		return true;
		%}

	function process_ack(m: Acknowledgment): bool
		%{
		${m.block}
		return true;
		%}

	function process_failure(opcode: uint16): bool
		%{
		connection()->bro_analyzer()->ProtocolViolation(fmt("Unknown opcode: %d", opcode));
		return true;
		%}

};

refine typeattr ReadRequest += &let {
	proc_read_request = $context.flow.process_read_request(this);
};

refine typeattr WriteRequest += &let {
	proc_write_request = $context.flow.process_write_request(this);
};

refine typeattr DataChunk += &let {
	proc_datachunk = $context.flow.process_datachunk(this);
};

refine typeattr FAILURE += &let {
	proc_failure = $context.flow.process_failure(opcode);
};