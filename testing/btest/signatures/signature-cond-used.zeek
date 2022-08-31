# @TEST-DOC: The function signature_cond used for eval in test.sig should not be reported as unused
# @TEST-EXEC: zeek -b %INPUT -r $TRACES/http/get.trace
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: btest-diff .stdout
module SignatureEvalTest;

@load-sigs ./test.sig

event signature_match(state: signature_state, msg: string, data: string)
        {
        print "signature_match", msg, data;
        }

function signature_cond(state: signature_state, data: string): bool
        {
        print "signature_cond", data;
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
@TEST-END-FILE
