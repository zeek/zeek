# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/connkey-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -NN Demo::Foo  >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -r $TRACES/ftp/ipv4.trace %INPUT >>output
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p id.ctx.inits id.inits proto service orig_pkts resp_pkts < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff output

redef ConnKey::factory = ConnKey::CONNKEY_FOO;

redef record conn_id += {
	inits: int &log &default=-1;  # Number of inits happened until the key was created. Not part of the hash, just metadata.
};

redef record conn_id_ctx += {
	inits: string &log &optional;
};
