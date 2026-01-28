# @TEST-DOC: Ensures modulo by 0 is an error.
#
# @TEST-EXEC-FAIL: unset ZEEK_ALLOW_INIT_ERRORS; zeek -b %INPUT
# @TEST-EXEC: btest-diff .stderr

event zeek_init() {
	# Cannot have second operand 0!
	modulo(0, 0);
}
