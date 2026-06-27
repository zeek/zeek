# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -f 'port 389' -r ${TRACES}/ldap/aduser1.pcap %INPUT
# @TEST-EXEC: mkdir krb && mv *.log krb
# @TEST-EXEC: zeek -f 'port 389' -r ${TRACES}/ldap/aduser1-ntlm.pcap %INPUT
# @TEST-EXEC: mkdir ntlm && mv *.log ntlm
# @TEST-EXEC: btest-diff krb/ldap.log
# @TEST-EXEC: btest-diff krb/ldap_search.log
# @TEST-EXEC: btest-diff-cut -m krb/kerberos.log
# @TEST-EXEC: btest-diff ntlm/ldap.log
# @TEST-EXEC: btest-diff ntlm/ldap_search.log
# @TEST-EXEC: btest-diff-cut -m ntlm/ntlm.log
#
# @TEST-DOC: Check two traces using different authentication mechanisms, but the same search request.
