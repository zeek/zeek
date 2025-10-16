/*
 * Verify that `-B all` leads to plugin debug stream content in debug.log.
 * This requires JavaScript and a debug build.
 * @TEST-REQUIRES: test "$($BUILD/zeek-config --build_type)" = "debug"
 * @TEST-REQUIRES: $SCRIPTS/have-javascript
 * @TEST-EXEC: LSAN_OPTIONS=${ZEEKJS_LSAN_OPTIONS} zeek -b -B all %INPUT
 * @TEST-EXEC: grep -q '[plugin Zeek::JavaScript]' debug.log
 */

zeek.on('zeek_init', () => {
  console.log('Hello Zeek!');
});
