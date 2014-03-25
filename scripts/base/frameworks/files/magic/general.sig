# General purpose file magic signatures.

signature file-plaintext {
    file-magic /([[:print:][:space:]]{10})/
    file-mime "text/plain", -20
}

signature file-tar {
    file-magic /([[:print:]\x00]){100}(([[:digit:]\x00\x20]){8}){3}/
    file-mime "application/x-tar", 150
}
