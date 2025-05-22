# Copyright (c) 2024 by the Zeek Project. See LICENSE for details.
#
# The ctu-sme-11-win7ad-1-ldap-tcp-50041.pcap file was harvested
# from the CTU-SME-11 (Experiment-VM-Microsoft-Windows7AD-1) dataset
# at https://zenodo.org/records/7958259 (DOI 10.5281/zenodo.7958258).

# @TEST-REQUIRES: have-spicy
# @TEST-EXEC: zeek -C -r ${TRACES}/ldap/ctu-sme-11-win7ad-1-ldap-tcp-50041.pcap
# @TEST-EXEC: cat conn.log | zeek-cut -Cn local_orig local_resp > conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ldap.log
# @TEST-EXEC: ! test -f analyzer.log
#
# @TEST-DOC: SASL bindRequest with SPNEGO NTLMSSP.
