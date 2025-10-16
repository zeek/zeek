/*
 * @TEST-REQUIRES: $SCRIPTS/have-javascript
 * @TEST-EXEC: LSAN_OPTIONS=${ZEEKJS_LSAN_OPTIONS} zeek -b %INPUT > out
 * @TEST-EXEC: btest-diff out
 */

zeek.on('zeek_init', () => {
  console.log('Hello Zeek!');
});
