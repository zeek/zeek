/*
 * @TEST-DOC: Demo suspend and continue processing from JavaScript
 * @TEST-REQUIRES: $SCRIPTS/have-javascript
 * @TEST-EXEC: zeek -b -Cr $TRACES/http/get.trace base/protocols/http %INPUT > out
 * @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
 */
zeek.on('zeek_init', () => {
  const nt = zeek.invoke('network_time');
  console.log(`${nt} suspend_processing`);
  zeek.invoke('suspend_processing');
  const suspended_at = Date.now();

  // Schedule a JavaScript timer (running based on wallclock)
  // to continue execution in 333 msec.
  setTimeout(() => {
    const nt = zeek.invoke('network_time');
    const continued_at = Date.now();
    const delayed_ms = continued_at - suspended_at;
    const delayed_enough = delayed_ms > 300;

    console.log(`${nt} continue_processing (delayed_enough=${delayed_enough})`);
    zeek.invoke('continue_processing');
  }, 333);
});

zeek.on('http_request', (c, method, orig_URI, escaped_URI, version) => {
  const nt = zeek.invoke('network_time');
  console.log(`${nt} http_request ${c.uid} ${method} ${orig_URI} ${version}`);
});

zeek.on('Pcap::file_done', (path) => {
  const nt = zeek.invoke('network_time');
  console.log(`${nt} Pcap::file_done ${path}`);
});

zeek.on('zeek_done', () => {
  const nt = zeek.invoke('network_time');
  console.log(`${nt} zeek_done`);
});
