%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/analyzer/protocol/bench/events.bif.h"
%}

analyzer BinpacBench withcontext {
  connection: Bench_Conn;
  flow:       Bench_Flow;
};

connection Bench_Conn(zeek_analyzer: ZeekAnalyzer) {
  upflow   = Bench_Flow(true);
  downflow = Bench_Flow(false);
};

type Bench_Header = record {
  version: uint8;
  id:      uint16;
  len:     uint32;
} &length=7;

type Bench_Request(hdr: Bench_Header) = record {
  data: bytestring &restofdata;
}

type Bench_Reply(hdr: Bench_Header) = record {
  data: bytestring &restofdata;
};

type Bench_Message(is_orig: bool) = record {
  hdr: Bench_Header;
  msg: case is_orig of {
    true -> request: Bench_Request(hdr);
    false -> reply: Bench_Reply(hdr);
  };
} &let {
  message_len = is_orig ? hdr.len : 7;
} &length=message_len &byteorder=bigendian;

flow Bench_Flow(is_orig: bool) {
  flowunit = Bench_Message(is_orig) withcontext(connection, this);

  function process_bench_request(r: Bench_Request): bool
    %{
    if ( ! bench_request )
      return true;

    zeek::StringValPtr data = zeek::make_intrusive<zeek::StringVal>(${r.data}.length(), (const char*)${r.data}.begin());

    zeek::BifEvent::enqueue_bench_request(
      connection()->zeek_analyzer(),
      connection()->zeek_analyzer()->Conn(),
      ${r.hdr.version},
      ${r.hdr.id},
      ${r.hdr.len},
      data);

    return true;
  %}

  function process_bench_reply(r: Bench_Reply): bool
    %{
    if ( ! bench_reply )
      return true;

    zeek::BifEvent::enqueue_bench_reply(
      connection()->zeek_analyzer(),
      connection()->zeek_analyzer()->Conn(),
      ${r.hdr.version},
      ${r.hdr.id},
      ${r.hdr.len});

    return true;
    %}
};

refine typeattr Bench_Request += &let {
  proc_bench_request = $context.flow.process_bench_request(this);
};

refine typeattr Bench_Reply += &let {
  proc_bench_request = $context.flow.process_bench_reply(this);
};
