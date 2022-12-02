# @TEST-DOC: The function signature_cond is used in two eval's in test.sig should not fail...
# @TEST-EXEC: unset ZEEK_ALLOW_INIT_ERRORS; zeek -b %INPUT -r $TRACES/http/get.trace
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: btest-diff .stdout
module SignatureEvalTest;

@load-sigs ./test.sig

event signature_match(state: signature_state, msg: string, data: string)
        {
        print "signature_match", msg, data[:32];
        }

function signature_cond(state: signature_state, data: string): bool
        {
        print "signature_cond", data[:32];
        return T;
        }


@TEST-START-FILE test.sig
signature my-first-sig {
        ip-proto == tcp
        dst-port == 80
        payload /GET/
        event "GET"
        eval SignatureEvalTest::signature_cond
}

signature my-second-sig {
        ip-proto == tcp
        payload /HTTP\/1\.1 [0-9]+/
        event "STATUS"
        eval SignatureEvalTest::signature_cond
}
@TEST-END-FILE
