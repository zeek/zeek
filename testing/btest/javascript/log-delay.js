/*
 * @TEST-DOC: Test delaying a log record from JavaScript
 * @TEST-REQUIRES: $SCRIPTS/have-javascript
 * @TEST-EXEC: LSAN_OPTIONS=${ZEEKJS_LSAN_OPTIONS} zeek -b -Cr $TRACES/http/get.trace main.zeek exit_only_after_terminate=T
 * @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
 * @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.resp_h new_field < http.log > http.log.cut
 * @TEST-EXEC: btest-diff http.log.cut
 */
// @TEST-START-FILE main.zeek
@load base/protocols/http

redef record HTTP::Info += {
  new_field: string &optional &log;
};

# Load the JavaScript pieces
@load ./main.js
// @TEST-END-FILE

// @TEST-START-FILE main.js
zeek.hook('Log::log_stream_policy', (rec, id) => {
  if ( id != "HTTP::LOG" )
    return;

  let nt = zeek.invoke('network_time');
  console.log(nt, 'delaying record');

  // Log::delay() of the in-flight write.
  let token = zeek.invoke('Log::delay', [id, rec]);

  // 10msec delayed record enrichment
  setTimeout(() => {
    let nt = zeek.invoke('network_time');
    rec.new_field = "JS: after delay";
    console.log(nt, 'delay finish');
    zeek.invoke('Log::delay_finish', [id, rec, token]);

    // Shutdown, too.
    zeek.invoke('terminate');
  }, 10);

});

zeek.hook('HTTP::log_policy', (rec, id, filter) => {
  let nt = zeek.invoke('network_time');
  console.log(nt, 'HTTP::log_policy', rec.uid, rec.id.orig_h, rec.id.resp_h, rec.new_field);
});

setTimeout(() => {
  console.error('force exit');
  process.exit(1);
}, 5000);
// @TEST-END-FILE
