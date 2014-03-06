# General purpose file magic signatures.

signature file-plaintext {
    file-magic /([[:print:][:space:]]+)/
    file-mime "text/plain", -20
}

signature file-binary {
    # Exclude bytes that can be ASCII or some ISO-8859 characters.
    file-magic /(.*)([^[:print:][:space:]\xa0-\xff]+)/
    file-mime "binary", -10
}

signature file-tar {
    file-magic /([[:print:]\x00]){100}(([[:digit:]\x00\x20]){8}){3}/
    file-mime "application/x-tar", 150
}
