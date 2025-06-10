# @TEST-DOC: Put a non-existing postprocessor function into a shadow file, ensure the default gets picked up. Regression test for #4562
#
# @TEST-EXEC: echo ".log" >> .shadow.conn.log
# @TEST-EXEC: echo "non_existing_rotation_postprocessor" >> .shadow.conn.log
# @TEST-EXEC: echo "leftover conn log" > conn.log
#
# @TEST-EXEC: echo ".log" >> .shadow.dns.log
# @TEST-EXEC: echo "wrongly_typed_rotation_postprocessor" >> .shadow.dns.log
# @TEST-EXEC: echo "leftover dns log" > dns.log
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-sort" btest-diff .stderr
#
# Ensure leftover files were removed.
# @TEST-EXEC: ! test -f .shadow.conn.log
# @TEST-EXEC: ! test -f conn.log
# @TEST-EXEC: ! test -f .shadow.dns.log
# @TEST-EXEC: ! test -f dns.log
#
# Ensure the rotated conn log ends-up in the current working directory.
# @TEST-EXEC: cat ./conn.*.log ./dns.*.log > logs.cat
# @TEST-EXEC: btest-diff logs.cat

function wrongly_typed_rotation_postprocessor(): bool
	{
	exit(1);
	return T;
	}

redef LogAscii::enable_leftover_log_rotation = T;
redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_date_format = "no-date";
