# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/utils/email

local s = "one@example.com two@example.com three@example.com one@example.com";
print extract_first_email_addr(s);
print extract_email_addrs_vec(s);
print extract_email_addrs_set(s);
s = "one@example.com,two@example.com,three@example.com,one@example.com";
print extract_first_email_addr(s);
print extract_email_addrs_vec(s);
print extract_email_addrs_set(s);
print split_mime_email_addresses(s);
s = "ieje one@example.com, eifj two@example.com, asdf three@example.com, one@example.com";
print extract_first_email_addr(s);
print extract_email_addrs_vec(s);
print extract_email_addrs_set(s);
s = "\"Smith, John\" <john.smith@email.com>, \"Doe, Jane\" <jane.doe@email.com>";
print extract_first_email_addr(s);
print extract_email_addrs_vec(s);
print extract_email_addrs_set(s);
print split_mime_email_addresses(s);
s = "\"Smith, John\" <john.smith@email.com>,\"Doe, Jane\" <jane.doe@email.com>";
print extract_first_email_addr(s);
print extract_email_addrs_vec(s);
print extract_email_addrs_set(s);
print split_mime_email_addresses(s);