# @TEST-DOC: Verify -V and --build-info work
# @TEST-EXEC: zeek -V  | python3 -m json.tool > V.json
# @TEST-EXEC: zeek --build-info | python3 -m json.tool > build-info.json
# @TEST-EXEC: diff V.json build-info.json
# @TEST-EXEC: grep -q '"commit"' V.json
