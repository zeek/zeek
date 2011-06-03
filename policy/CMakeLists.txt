install(DIRECTORY ./ DESTINATION ${POLICYDIR} FILES_MATCHING
        PATTERN "summaries" EXCLUDE
        PATTERN "all.bro" EXCLUDE
        PATTERN "bro.init"
        PATTERN "*.bro"
        PATTERN "*.sig"
        PATTERN "*.osf"
)

install(DIRECTORY DESTINATION ${POLICYDIR}/site)
