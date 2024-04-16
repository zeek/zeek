# This file loads ALL policy scripts that are part of the Zeek distribution.
#
# This is rarely makes sense, and is for testing only.
#
# Note that we have a unit test that makes sure that all policy files shipped are
# actually loaded here. If we have files that are part of the distribution yet
# can't be loaded here,  these must still be listed here with their load command
# commented out.

# The base/ scripts are all loaded by default and not included here.

# @load frameworks/control/controllee.zeek
# @load frameworks/control/controller.zeek
@load frameworks/cluster/experimental.zeek
# Loaded via the above through test-all-policy-cluster.test
# when running as a manager, creates cluster.log entries
# even in non-cluster mode if loaded like the below.
# @load frameworks/cluster/nodes-experimental/manager.zeek
@load frameworks/management/agent/__load__.zeek
@load frameworks/management/agent/api.zeek
@load frameworks/management/agent/boot.zeek
@load frameworks/management/agent/config.zeek
# @load frameworks/management/agent/main.zeek
@load frameworks/management/controller/__load__.zeek
@load frameworks/management/controller/api.zeek
@load frameworks/management/controller/boot.zeek
@load frameworks/management/controller/config.zeek
# @load frameworks/management/controller/main.zeek
@load frameworks/management/__load__.zeek
@load frameworks/management/config.zeek
@load frameworks/management/log.zeek
@load frameworks/management/persistence.zeek
# @load frameworks/management/node/__load__.zeek
@load frameworks/management/node/api.zeek
@load frameworks/management/node/config.zeek
# @load frameworks/management/node/main.zeek
@load frameworks/management/supervisor/__load__.zeek
@load frameworks/management/supervisor/api.zeek
@load frameworks/management/supervisor/config.zeek
@load frameworks/management/supervisor/main.zeek
@load frameworks/management/request.zeek
@load frameworks/management/types.zeek
@load frameworks/management/util.zeek
@load frameworks/dpd/detect-protocols.zeek
@load frameworks/dpd/packet-segment-logging.zeek
@load frameworks/intel/do_notice.zeek
@load frameworks/intel/do_expire.zeek
@load frameworks/intel/whitelist.zeek
@load frameworks/intel/removal.zeek
@load frameworks/intel/seen/__load__.zeek
@load frameworks/intel/seen/conn-established.zeek
@load frameworks/intel/seen/dns.zeek
@load frameworks/intel/seen/file-hashes.zeek
@load frameworks/intel/seen/file-names.zeek
@load frameworks/intel/seen/http-headers.zeek
@load frameworks/intel/seen/http-url.zeek
@load frameworks/intel/seen/pubkey-hashes.zeek
@load frameworks/intel/seen/smb-filenames.zeek
@load frameworks/intel/seen/smtp-url-extraction.zeek
@load frameworks/intel/seen/smtp.zeek
@load frameworks/intel/seen/ssl.zeek
@load frameworks/intel/seen/where-locations.zeek
@load frameworks/intel/seen/x509.zeek
@load frameworks/netcontrol/catch-and-release.zeek
@load frameworks/files/detect-MHR.zeek
@load frameworks/files/entropy-test-all-files.zeek
#@load frameworks/files/extract-all-files.zeek
@load frameworks/files/hash-all-files.zeek
@load frameworks/notice/__load__.zeek
@load frameworks/notice/actions/drop.zeek
@load frameworks/notice/community-id.zeek
@load frameworks/notice/extend-email/hostnames.zeek
@load files/x509/disable-certificate-events-known-certs.zeek
@load frameworks/packet-filter/shunt.zeek
# @load frameworks/signatures/iso-9660.zeek
@load frameworks/software/version-changes.zeek
@load frameworks/software/vulnerable.zeek
# @load frameworks/spicy/record-spicy-batch.zeek
# @load frameworks/spicy/resource-usage.zeek
@load frameworks/software/windows-version-detection.zeek
@load frameworks/telemetry/prometheus.zeek
@load frameworks/telemetry/log.zeek
@load integration/collective-intel/__load__.zeek
@load integration/collective-intel/main.zeek
@load misc/capture-loss.zeek
@load misc/detect-traceroute/__load__.zeek
@load misc/detect-traceroute/main.zeek
# @load misc/dump-events.zeek
@load misc/load-balancing.zeek
@load misc/loaded-scripts.zeek
@load misc/profiling.zeek
@load misc/stats.zeek
@load misc/weird-stats.zeek
@load misc/trim-trace-file.zeek
@load misc/unknown-protocols.zeek
@load protocols/conn/community-id-logging.zeek
@load protocols/conn/known-hosts.zeek
@load protocols/conn/known-services.zeek
@load protocols/conn/mac-logging.zeek
@load protocols/conn/vlan-logging.zeek
@load protocols/conn/weirds.zeek
#@load protocols/conn/speculative-service.zeek
@load protocols/dhcp/msg-orig.zeek
@load protocols/dhcp/software.zeek
@load protocols/dhcp/sub-opts.zeek
@load protocols/dns/auth-addl.zeek
@load protocols/dns/detect-external-names.zeek
@load protocols/dns/log-original-query-case.zeek
@load protocols/ftp/detect-bruteforcing.zeek
@load protocols/ftp/detect.zeek
@load protocols/ftp/software.zeek
@load protocols/http/detect-sqli.zeek
@load protocols/http/detect-webapps.zeek
@load protocols/http/header-names.zeek
@load protocols/http/software-browser-plugins.zeek
@load protocols/http/software.zeek
@load protocols/http/var-extraction-cookies.zeek
@load protocols/http/var-extraction-uri.zeek
@load protocols/krb/ticket-logging.zeek
@load protocols/modbus/known-masters-slaves.zeek
@load protocols/modbus/track-memmap.zeek
@load protocols/mysql/software.zeek
@load protocols/rdp/indicate_ssl.zeek
@load protocols/smb/log-cmds.zeek
@load protocols/smtp/blocklists.zeek
@load protocols/smtp/detect-suspicious-orig.zeek
@load protocols/smtp/entities-excerpt.zeek
@load protocols/smtp/software.zeek
@load protocols/ssh/detect-bruteforcing.zeek
@load protocols/ssh/geo-data.zeek
@load protocols/ssh/interesting-hostnames.zeek
@load protocols/ssh/software.zeek
@load protocols/ssl/certificate-request-info.zeek
@load protocols/ssl/decryption.zeek
@load protocols/ssl/expiring-certs.zeek
@load protocols/ssl/heartbleed.zeek
@load protocols/ssl/known-certs.zeek
@load protocols/ssl/log-certs-base64.zeek
@load protocols/ssl/ssl-log-ext.zeek
@load protocols/ssl/log-hostcerts-only.zeek
@load protocols/ssl/validate-certs.zeek
@load protocols/ssl/validate-ocsp.zeek
@load protocols/ssl/validate-sct.zeek
@load protocols/ssl/weak-keys.zeek
@load tuning/__load__.zeek
@load tuning/defaults/__load__.zeek
@load tuning/defaults/extracted_file_limits.zeek
@load tuning/defaults/packet-fragments.zeek
@load tuning/defaults/warnings.zeek
@load tuning/json-logs.zeek
@load tuning/track-all-assets.zeek
