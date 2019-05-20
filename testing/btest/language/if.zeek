# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

function test_case(msg: string, expect: bool)
        {
        print fmt("%s (%s)", msg, expect ? "PASS" : "FAIL");
        }



event zeek_init()
{
	# Test "if" without "else"

	if ( T ) test_case( "if T", T);

	if ( F ) test_case( "Error: this should not happen", F);

	# Test "if" with only an "else"

	if ( T ) test_case( "if T else", T);
	else test_case( "Error: this should not happen", F);

	if ( F ) test_case( "Error: this should not happen", F);
	else test_case( "if F else", T);

	# Test "if" with only an "else if"

	if ( T ) test_case( "if T else if F", T);
	else if ( F ) test_case( "Error: this should not happen", F);

	if ( F ) test_case( "Error: this should not happen", F);
	else if ( T ) test_case( "if F else if T", T);

	if ( T ) test_case( "if T else if T", T);
	else if ( T ) test_case( "Error: this should not happen", F);

	if ( F ) test_case( "Error: this should not happen", F);
	else if ( F ) test_case( "Error: this should not happen", F);

	# Test "if" with both "else if" and "else"

	if ( T ) test_case( "if T else if F else", T);
	else if ( F ) test_case( "Error: this should not happen", F);
	else test_case( "Error: this should not happen", F);

	if ( F ) test_case( "Error: this should not happen", F);
	else if ( T ) test_case( "if F else if T else", T);
	else test_case( "Error: this should not happen", F);

	if ( T ) test_case( "if T else if T else", T);
	else if ( T ) test_case( "Error: this should not happen", F);
	else test_case( "Error: this should not happen", F);

	if ( F ) test_case( "Error: this should not happen", F);
	else if ( F ) test_case( "Error: this should not happen", F);
	else test_case( "if F else if F else", T);

	# Test "if" with multiple "else if" and an "else"

	if ( F ) test_case( "Error: this should not happen", F);
	else if ( F ) test_case( "Error: this should not happen", F);
	else if ( T ) test_case( "if F else if F else if T else", T);
	else test_case( "Error: this should not happen", F);

	if ( F ) test_case( "Error: this should not happen", F);
	else if ( F ) test_case( "Error: this should not happen", F);
	else if ( F ) test_case( "Error: this should not happen", F);
	else test_case( "if F else if F else if F else", T);
}

