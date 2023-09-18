LDAP Analyzer
=============

Here's what it has:

- ASN.1 structure decoding: this is probably generally useful for more than just the LDAP parser, so it may be of interest for this to be included somehow as part of spicy's standard modules or whatever
  - everything is working except for the "constructed" forms of `ASN1BitString` and `ASN1OctetString`
- LDAP: the LDAP parsing is basically "done once" through a single call to `ASN1Message` (which parses itself recursively) and then the application-level data is also parsed via `&parse-from` a byte array belonging to the outer ASN.1 sequence. This second level of parsing is also done using the ASN.1 data types.
  - events
    - `ldap::message` - called for each LDAP message
    - `ldap::bindreq` - when a bind request is made
    - `ldap::searchreq` - basic search request information
    - `ldap::searchres` - called each time a search result is returned
  - enums
    - `ProtocolOpcode`
    - `ResultCode`
    - `BindAuthType`
    - `SearchScope`
    - `SearchDerefAlias`
    - `FilterType`
  - Zeek log files
    - `ldap.log` - contains information about all LDAP messages except those that are search-related. Log lines are grouped by connection ID + message ID
      - `ts` (time)
      - `uid` (connection UID)
      - `id` (connection ID 4-tuple)
      - `proto` (transport protocol)
      - `message_id` (LDAP message ID)
      - `version` (LDAP version for bind requests)
      - `opcode` (set of 1..n operations from this uid+message_id)
      - `result` (set of 1..n results from this uid+message_id)
      - `diagnostic_message` (vector of 0..n diagnostic message strings)
      - `object` (vector of 0..n "objects," the meaning of which depends on the operation)
      - `argument` (vector of 0..n "argument," the meaning of which depends on the operation)
    - `ldap_search.log` - contains information about LDAP searches. Log lines are grouped by connection ID + message ID
      - `ts` (time)
      - `uid` (connection UID)
      - `id` (connection ID 4-tuple)
      - `proto` (transport protocol)
      - `message_id` (LDAP message ID)
      - `scope` (set of 1..n search scopes defined in this uid+message_id)
      - `deref` (set of 1..n search deref alias options defined in this uid+message_id)
      - `base_object` (vector of 0..n search base objects specified)
      - `result_count` (number of result entries returned)
      - `result` (set of 1..n results from this uid+message_id)
      - `diagnostic_message` (vector of 0..n diagnostic message strings)
      - `filter` (search filter string)
      - `attributes` (vector of 0..n "attributes", the attributes that were returned)
  - test
    - basic tests for detecting plugin presence and simple bind and search result/requests

Here's what it doesn't have, which could be added by future parties interested in expanding it:

- LDAP [referrals](https://tools.ietf.org/html/rfc4511#section-4.1.10) are not parsed out of the results
- [SASL credentials](https://datatracker.ietf.org/doc/html/rfc4511#section-4.2) in bind requests are not being parsed beyond the mechanism string
- SASL information in bind responses are not being parsed; for that matter, SASL-based LDAP stuff hasn't been tested much and may have issues
- Search filters and attributes: the search filters, reconstructed from the query tree, is represented in string format. The AND and OR filters have a tree structure and are parsed with the `ParseNestedAndOr` unit, whereas the NOT filter consist of one single nested SearchFilter and is parsed with a `ParseNestedNot` unit. The remaining filter types can all be decoded to a string using the `DecodedAttributeValue` unit, which takes the `FilterType` as a parameter. The `FILTER_PRESENT` consists of a single octet string and can be parsed directly. By recursively constructing leafs and nodes in the tree, the final search filter can be represented, e.g. `(&(objectclass=*)(sAMAccountName=xxxxxxxx))`. The returned attributes are represented in a list and returned to the `ldap_search.log` if `option default_log_search_attributes = T;` is set (the default is False).
- the details of `SearchResultReference` are not being parsed
- the only detail of `ModifyRequest` being parsed is the object name
- the details of `AddRequest` are not being parsed
- the details of `ModDNRequest` are not being parsed
- the details of `CompareRequest` are not being parsed
- the details of `AbandonRequest` are not being parsed
- the details of `ExtendedRequest` are not being parsed
- the details of `ExtendedResponse` are not being parsed
- the details of `IntermediateResponse` are not being parsed
- [Logging policy](https://docs.zeek.org/en/master/frameworks/logging.html#filtering-log-records) is available.

Useful Links:

- <https://luca.ntop.org/Teaching/Appunti/asn1.html>
- <https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf>
- <https://tools.ietf.org/html/rfc4511#>
- <https://ldap.com/ldapv3-wire-protocol-reference-asn1-ber/>
- <https://lapo.it/asn1js>
