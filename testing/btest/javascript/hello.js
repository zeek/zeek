/*
 * @TEST-REQUIRES: $SCRIPTS/have-javascript
 * @TEST-EXEC: zeek -b %INPUT > out
 * @TEST-EXEC: btest-diff out
 */

zeek.on('zeek_init', () => {
  console.log('Hello Zeek!');
});
