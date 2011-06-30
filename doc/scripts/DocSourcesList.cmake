# This is a list of Bro script sources for which to generate reST documentation.
# It will be included inline in the CMakeLists.txt found in the same directory
# in order to create Makefile targets that define how to generate reST from
# a given Bro script.
#
# Note: any path prefix of the script (2nd argument of rest_target macro)
# will be used to derive what path under policy/ the generated documentation
# will be placed.

set(psd ${PROJECT_SOURCE_DIR}/policy)

rest_target(${CMAKE_CURRENT_SOURCE_DIR} example.bro internal)

rest_target(${CMAKE_BINARY_DIR}/src bro.bif.bro)
rest_target(${CMAKE_BINARY_DIR}/src const.bif.bro)
rest_target(${CMAKE_BINARY_DIR}/src event.bif.bro)
rest_target(${CMAKE_BINARY_DIR}/src logging.bif.bro)
rest_target(${CMAKE_BINARY_DIR}/src strings.bif.bro)
rest_target(${CMAKE_BINARY_DIR}/src types.bif.bro)

rest_target(${psd} bro.init)
rest_target(${psd} functions.bro)
rest_target(${psd} site.bro)

rest_target(${psd} detectors/http-MHR.bro)

rest_target(${psd} frameworks/communication/base.bro)
rest_target(${psd} frameworks/communication/listen-clear.bro)
rest_target(${psd} frameworks/communication/listen-ssl.bro)

rest_target(${psd} frameworks/dpd/base.bro)
rest_target(${psd} frameworks/dpd/dyn-disable.bro)
rest_target(${psd} frameworks/dpd/packet-segment-logging.bro)

rest_target(${psd} frameworks/intel/base.bro)

rest_target(${psd} frameworks/logging/base.bro)
rest_target(${psd} frameworks/logging/plugins/ascii.bro)

rest_target(${psd} frameworks/metrics/base.bro)
rest_target(${psd} frameworks/metrics/conn-example.bro)
rest_target(${psd} frameworks/metrics/http-example.bro)

rest_target(${psd} frameworks/notice/action-filters.bro)
rest_target(${psd} frameworks/notice/base.bro)
rest_target(${psd} frameworks/notice/weird.bro)

rest_target(${psd} frameworks/packet-filter/base.bro)
rest_target(${psd} frameworks/packet-filter/netstats.bro)

rest_target(${psd} frameworks/signatures/base.bro)

rest_target(${psd} frameworks/software/base.bro)
rest_target(${psd} frameworks/software/vulnerable.bro)

rest_target(${psd} integration/barnyard2/base.bro)
rest_target(${psd} integration/barnyard2/event.bro)
rest_target(${psd} integration/barnyard2/types.bro)

rest_target(${psd} protocols/conn/base.bro)
rest_target(${psd} protocols/conn/contents.bro)
rest_target(${psd} protocols/conn/inactivity.bro)
rest_target(${psd} protocols/conn/known-hosts.bro)
rest_target(${psd} protocols/conn/known-services.bro)

rest_target(${psd} protocols/dns/auth-addl.bro)
rest_target(${psd} protocols/dns/base.bro)
rest_target(${psd} protocols/dns/consts.bro)
rest_target(${psd} protocols/dns/detect.bro)

rest_target(${psd} protocols/ftp/base.bro)
rest_target(${psd} protocols/ftp/detect.bro)
rest_target(${psd} protocols/ftp/file-extract.bro)
rest_target(${psd} protocols/ftp/software.bro)
rest_target(${psd} protocols/ftp/utils-commands.bro)

rest_target(${psd} protocols/http/base.bro)
rest_target(${psd} protocols/http/detect-intel.bro)
rest_target(${psd} protocols/http/detect-sqli.bro)
rest_target(${psd} protocols/http/detect-webapps.bro)
rest_target(${psd} protocols/http/file-extract.bro)
rest_target(${psd} protocols/http/file-hash.bro)
rest_target(${psd} protocols/http/file-ident.bro)
rest_target(${psd} protocols/http/headers.bro)
rest_target(${psd} protocols/http/software.bro)
rest_target(${psd} protocols/http/utils.bro)
rest_target(${psd} protocols/http/var-extraction-cookies.bro)
rest_target(${psd} protocols/http/var-extraction-uri.bro)

rest_target(${psd} protocols/irc/base.bro)
rest_target(${psd} protocols/irc/dcc-send.bro)

rest_target(${psd} protocols/mime/base.bro)
rest_target(${psd} protocols/mime/file-extract.bro)
rest_target(${psd} protocols/mime/file-hash.bro)
rest_target(${psd} protocols/mime/file-ident.bro)

rest_target(${psd} protocols/smtp/base.bro)
rest_target(${psd} protocols/smtp/detect.bro)
rest_target(${psd} protocols/smtp/software.bro)

rest_target(${psd} protocols/ssh/base.bro)
rest_target(${psd} protocols/ssh/software.bro)

#rest_target(${psd} protocols/ssl/base.bro)
#rest_target(${psd} protocols/ssl/ssl-ciphers.bro)
#rest_target(${psd} protocols/ssl/ssl-errors.bro)
#rest_target(${psd} protocols/ssl/ssl.bro)
#rest_target(${psd} protocols/ssl/validate.bro)

rest_target(${psd} protocols/syslog/base.bro)
rest_target(${psd} protocols/syslog/consts.bro)

rest_target(${psd} tuning/defaults/packet-fragments.bro)
rest_target(${psd} tuning/defaults/remove-high-volume-notices.bro)
rest_target(${psd} tuning/track-all-assets.bro)

rest_target(${psd} utils/addrs.bro)
rest_target(${psd} utils/conn_ids.bro)
rest_target(${psd} utils/directions-and-hosts.bro)
rest_target(${psd} utils/files.bro)
rest_target(${psd} utils/numbers.bro)
rest_target(${psd} utils/paths.bro)
rest_target(${psd} utils/pattern.bro)
rest_target(${psd} utils/strings.bro)
rest_target(${psd} utils/thresholds.bro)
