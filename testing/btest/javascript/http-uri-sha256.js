/*
 * @TEST-REQUIRES: $SCRIPTS/have-javascript
 * @TEST-EXEC: zeek -b -Cr $TRACES/http/get.trace main.zeek LogAscii::use_json=T
 * @TEST-EXEC: btest-diff http.log
 */
@TEST-START-FILE main.zeek
@load base/protocols/http

# Extending log records only works in Zeek script.
redef record HTTP::Info += {
  ## The sha256 value of the orig_URI.
  uri_sha256: string &optional &log;
};

# Load the JavaScript pieces
@load ./main.js
@TEST-END-FILE

@TEST-START-FILE main.js
const crypto = require('crypto');

/*
 * We can set fields directly on c.http from JavaScript and they'll appear
 * in the http.log record. In this case, we compute the sha256 hash of
 * the orig_URI and log it.
 */
zeek.on('http_request', { priority: -10 }, (c, method, orig_URI, escaped_URI, version) => {
  c.http.uri_sha256 = crypto.createHash('sha256').update(orig_URI).digest().toString('hex');
});
@TEST-END-FILE
