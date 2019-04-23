:tocdepth: 3

base/protocols/krb/consts.zeek
==============================
.. zeek:namespace:: KRB


:Namespace: KRB

Summary
~~~~~~~
Constants
#########
=============================================== =
:zeek:id:`KRB::cipher_name`: :zeek:type:`table` 
:zeek:id:`KRB::error_msg`: :zeek:type:`table`   
=============================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: KRB::cipher_name

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Default:

   ::

      {
         [2] = "des-cbc-md4",
         [9] = "dsaWithSHA1-CmsOID",
         [17] = "aes128-cts-hmac-sha1-96",
         [11] = "sha1WithRSAEncryption-CmsOID",
         [14] = "rsaES-OAEP-ENV-OID",
         [24] = "rc4-hmac-exp",
         [1] = "des-cbc-crc",
         [7] = "des3-cbc-sha1",
         [15] = "des-ede3-cbc-Env-OID",
         [23] = "rc4-hmac",
         [5] = "des3-cbc-md5",
         [25] = "camellia128-cts-cmac",
         [10] = "md5WithRSAEncryption-CmsOID",
         [65] = "subkey-keymaterial",
         [3] = "des-cbc-md5",
         [12] = "rc2CBC-EnvOID",
         [13] = "rsaEncryption-EnvOID",
         [18] = "aes256-cts-hmac-sha1-96",
         [16] = "des3-cbc-sha1-kd",
         [26] = "camellia256-cts-cmac"
      }


.. zeek:id:: KRB::error_msg

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Default:

   ::

      {
         [19] = "KDC_ERR_SERVICE_REVOKED",
         [10] = "KDC_ERR_CANNOT_POSTDATE",
         [3] = "KDC_ERR_BAD_PVNO",
         [50] = "KRB_AP_ERR_INAPP_CKSUM",
         [69] = "KRB_AP_ERR_USER_TO_USER_REQUIRED",
         [47] = "KRB_AP_ERR_BADDIRECTION",
         [27] = "KDC_ERR_MUST_USE_USER2USER",
         [67] = "KRB_AP_ERR_NO_TGT",
         [70] = "KDC_ERR_CANT_VERIFY_CERTIFICATE",
         [6] = "KDC_ERR_C_PRINCIPAL_UNKNOWN",
         [66] = "KDC_ERR_CERTIFICATE_MISMATCH",
         [20] = "KDC_ERR_TGT_REVOKED",
         [51] = "KRB_AP_PATH_NOT_ACCEPTED",
         [25] = "KDC_ERR_PREAUTH_REQUIRED",
         [37] = "KRB_AP_ERR_SKEW",
         [31] = "KRB_AP_ERR_BAD_INTEGRITY",
         [63] = "KDC_ERROR_KDC_NOT_TRUSTED",
         [28] = "KDC_ERR_PATH_NOT_ACCEPTED",
         [68] = "KDC_ERR_WRONG_REALM",
         [9] = "KDC_ERR_NULL_KEY",
         [11] = "KDC_ERR_NEVER_VALID",
         [40] = "KRB_AP_ERR_MSG_TYPE",
         [41] = "KRB_AP_ERR_MODIFIED",
         [46] = "KRB_AP_ERR_MUT_FAIL",
         [5] = "KDC_ERR_S_OLD_MAST_KVNO",
         [49] = "KRB_AP_ERR_BADSEQ",
         [45] = "KRB_AP_ERR_NOKEY",
         [8] = "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
         [17] = "KDC_ERR_TRTYPE_NOSUPP",
         [48] = "KRB_AP_ERR_METHOD",
         [33] = "KRB_AP_ERR_TKT_NYV",
         [24] = "KDC_ERR_PREAUTH_FAILED",
         [23] = "KDC_ERR_KEY_EXPIRED",
         [26] = "KDC_ERR_SERVER_NOMATCH",
         [0] = "KDC_ERR_NONE",
         [39] = "KRB_AP_ERR_BADVERSION",
         [16] = "KDC_ERR_PADATA_TYPE_NOSUPP",
         [34] = "KRB_AP_ERR_REPEAT",
         [38] = "KRB_AP_ERR_BADADDR",
         [18] = "KDC_ERR_CLIENT_REVOKED",
         [35] = "KRB_AP_ERR_NOT_US",
         [42] = "KRB_AP_ERR_BADORDER",
         [71] = "KDC_ERR_INVALID_CERTIFICATE",
         [74] = "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE",
         [7] = "KDC_ERR_S_PRINCIPAL_UNKNOWN",
         [15] = "KDC_ERR_SUMTYPE_NOSUPP",
         [36] = "KRB_AP_ERR_BADMATCH",
         [62] = "KDC_ERROR_CLIENT_NOT_TRUSTED",
         [4] = "KDC_ERR_C_OLD_MAST_KVNO",
         [44] = "KRB_AP_ERR_BADKEYVER",
         [52] = "KRB_ERR_RESPONSE_TOO_BIG",
         [1] = "KDC_ERR_NAME_EXP",
         [64] = "KDC_ERROR_INVALID_SIG",
         [22] = "KDC_ERR_SERVICE_NOTYET",
         [72] = "KDC_ERR_REVOKED_CERTIFICATE",
         [14] = "KDC_ERR_ETYPE_NOSUPP",
         [73] = "KDC_ERR_REVOCATION_STATUS_UNKNOWN",
         [76] = "KDC_ERR_KDC_NAME_MISMATCH",
         [21] = "KDC_ERR_CLIENT_NOTYET",
         [29] = "KDC_ERR_SVC_UNAVAILABLE",
         [13] = "KDC_ERR_BADOPTION",
         [75] = "KDC_ERR_CLIENT_NAME_MISMATCH",
         [2] = "KDC_ERR_SERVICE_EXP",
         [32] = "KRB_AP_ERR_TKT_EXPIRED",
         [60] = "KRB_ERR_GENERIC",
         [12] = "KDC_ERR_POLICY",
         [61] = "KRB_ERR_FIELD_TOOLONG",
         [65] = "KDC_ERR_KEY_TOO_WEAK"
      }



