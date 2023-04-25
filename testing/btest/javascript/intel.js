/*
 * @TEST-DOC: Load intel data from a JSON file and populate via Intel::insert().
 * @TEST-REQUIRES: $SCRIPTS/have-javascript
 * @TEST-EXEC: zeek -b -Cr $TRACES/http/get.trace frameworks/intel/seen base/frameworks/intel base/protocols/http %INPUT
 * @TEST-EXEC: zeek-cut < intel.log > intel.log.noheader
 * @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff intel.log.noheader
 *
 * Following the intel file that we load via Intel::insert().
@TEST-START-FILE intel.json_lines
{"indicator": "141.142.228.5", "indicator_type": "Intel::ADDR", "meta": {"source": "json1"}}
{"indicator": "bro.org", "indicator_type": "Intel::DOMAIN", "meta": {"source": "json2"}}
@TEST-END-FILE
*/
const fs = require('fs');

zeek.on('zeek_init', () => {
  // Hold the packet processing until we've read the intel file.
  zeek.invoke('suspend_processing');

  // This reads the full file into memory, but is still async.
  // There's fs.createReadStream() for the piecewise consumption.
  fs.readFile('./intel.json_lines', 'utf8', (err, data) => {
    for (const l of data.split('\n')) {
      if (l.length == 0)
        continue;

      zeek.invoke('Intel::insert', [JSON.parse(l)]);
    }

    /* Once all intel data is loaded, continue processing. */
    zeek.invoke('continue_processing');
  });
});
