
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

	function process_tftp_message(m: TFTP_Message): bool
		%{
		//printf("blah: %d\n", ${m.opcode});
		//BifEvent::generate_syslog_message(connection()->bro_analyzer(),
		//                                  connection()->bro_analyzer()->Conn(),
		//                                  ${m.PRI.facility},
		//                                  ${m.PRI.severity},
		//                                  new StringVal(${m.msg}.length(), (const char*) //${m.msg}.begin())
		//                                  );
		return true;
		%}

	function process_read_request(m: ReadRequest): bool
		%{
		BifEvent::generate_tftp_read_request(connection()->bro_analyzer(),
		                                     connection()->bro_analyzer()->Conn(),
		                                     bytestring_to_val(${m.file}),
		                                     bytestring_to_val(${m.type}));
		return true;
		%}

	function process_write_request(m: WriteRequest): bool
		%{
		BifEvent::generate_tftp_write_request(connection()->bro_analyzer(),
		                                      connection()->bro_analyzer()->Conn(),
		                                      bytestring_to_val(${m.file}),
		                                      bytestring_to_val(${m.type}));
		return true;
		%}

	function process_datachunk(m: DataChunk): bool
		%{
		//file_mgr->DataIn(reinterpret_cast<const u_char*>(${m.data}.begin(), 
		//                 (uint64) ${m.data}.length(), 
		//                 (uint64) ${m.block}*512,
		//                 connection()->bro_analyzer()->GetAnalyzerTag(),
		//                 connection()->bro_analyzer()->Conn(),
		//                 true));
		return true;
		%}

};

refine typeattr TFTP_Message += &let {
	proc_tftp_message = $context.flow.process_tftp_message(this);
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