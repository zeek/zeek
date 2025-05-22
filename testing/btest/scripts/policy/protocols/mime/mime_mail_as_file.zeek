# @TEST-EXEC: zeek -C -b -r $TRACES/smtp-attachment-msg.pcap base/protocols/smtp policy/protocols/mime/mime_mail_as_file
# @TEST-EXEC: grep -q message/rfc822 files.log
