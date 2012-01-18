# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

global default_alphabet: string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

global my_alphabet: string = "!#$%&/(),-.:;<>@[]^ `_{|}~abcdefghijklmnopqrstuvwxyz0123456789+?";

print decode_base64("YnJv");
print decode_base64_custom("YnJv", default_alphabet);
print decode_base64_custom("}n-v", my_alphabet);

print decode_base64("YnJv");
print decode_base64_custom("YnJv", default_alphabet);
print decode_base64_custom("}n-v", my_alphabet);
