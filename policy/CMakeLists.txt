install(DIRECTORY . DESTINATION ${DATADIR} FILES_MATCHING
        PATTERN "summaries" EXCLUDE
        PATTERN "all.bro" EXCLUDE
        PATTERN "bro.init"
        PATTERN "*.bro"
        PATTERN "*.sig"
        PATTERN "*.osf"
)

install(DIRECTORY DESTINATION ${DATADIR}/site)
