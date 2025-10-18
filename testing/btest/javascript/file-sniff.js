/*
 * @TEST-REQUIRES: $SCRIPTS/have-javascript
 * @TEST-EXEC: LSAN_OPTIONS=${ZEEKJS_LSAN_OPTIONS} zeek -b -Cr $TRACES/http/get.trace base/protocols/http ./ext.zeek %INPUT > out
 * @TEST-EXEC: zeek-cut -m fuid uid from_js < files.log > files.log.cut
 * @TEST-EXEC: btest-diff out
 * @TEST-EXEC: btest-diff files.log.cut
 */

zeek.on('file_sniff', (f, meta) => {
  console.log(`file_sniff ${f.id} ${JSON.stringify(meta)}`);
});

zeek.on('file_state_remove', (f) => {
  console.log(`file_state_remove ${f.id}`);
  f.info.from_js = "Hello from JavaScript";
});

// @TEST-START-FILE ext.zeek
redef record Files::Info += {
  from_js: string &log &optional;
};
// @TEST-END-FILE
