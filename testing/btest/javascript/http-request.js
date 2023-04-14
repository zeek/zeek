/*
 * @TEST-REQUIRES: $SCRIPTS/have-javascript
 * @TEST-EXEC: zeek -b -Cr $TRACES/http/get.trace base/protocols/http %INPUT > out
 * @TEST-EXEC: btest-diff out
 */

zeek.on('http_request', (c, method, orig_URI, escaped_URI, version) => {
  console.log(`http_request ${c.uid} ${method} ${orig_URI} ${version}`);
});
