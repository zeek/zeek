%extern{
#include <cstdlib>
#include <vector>
#include <string>
#include "zeek/digest.h"
#include "zeek/Base64.h"

#include "zeek/analyzer/protocol/ssh/consts.bif.h"
%}

%header{
// max_size = 0 is unlimited, otherwise extract at most max_size elements into the result
// and if reached raise a weird with weird_name.
zeek::VectorValPtr name_list_to_vector(const bytestring& nl, size_t max_size,
                                       const char* weird_name,
                                       zeek::analyzer::Analyzer* a);
const char* fingerprint_md5(const unsigned char* d);
%}

%code{
zeek::VectorValPtr name_list_to_vector(const bytestring& nl, size_t max_size,
                                       const char* weird_name,
                                       zeek::analyzer::Analyzer* a)
	{
	auto vv = zeek::make_intrusive<zeek::VectorVal>(zeek::id::string_vec);

	std::string_view sv{reinterpret_cast<const char*>(nl.begin()), static_cast<size_t>(nl.length())};
	auto sv_words = zeek::util::tokenize_string(sv, ',');

	for ( auto word : sv_words ) {
		if ( max_size == 0 || vv->Size() < max_size ) {
			vv->Append(zeek::make_intrusive<zeek::StringVal>(word));
		} else {
			const char* addl = max_size > 0 ? zeek::util::fmt("%zu > %zu", sv_words.size(), max_size) : zeek::util::fmt("%zu", sv_words.size());
			a->Conn()->CheckHistory(zeek::session::detail::HIST_UNKNOWN_PKT, 'X');
			a->Weird(weird_name, addl);
			break;
		}
	}

	return vv;
	}

const char* fingerprint_md5(const unsigned char* d)
	{
	return zeek::util::fmt("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
	                       "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
	                       d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
	                       d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);
	}
%}

refine flow SSH_Flow += {
	function cap_packet_length(len: uint32): uint32
		%{
		uint32_t max_len = zeek::BifConst::SSH::max_packet_length;

		if ( max_len > 0 && len > max_len ) {
			auto *a = connection()->zeek_analyzer();
			a->Conn()->CheckHistory(zeek::session::detail::HIST_UNKNOWN_PKT, 'X');
			a->Weird("SSH_max_packet_length_exceeded", zeek::util::fmt("%u > %u", len, max_len));

			len = max_len;
		}

		return len;
		%}

	function cap_string_length(len: uint32): uint32
		%{
		uint32_t max_len = zeek::BifConst::SSH::max_string_length;

		if ( max_len > 0 && len > max_len ) {
			auto *a = connection()->zeek_analyzer();
			a->Conn()->CheckHistory(zeek::session::detail::HIST_UNKNOWN_PKT, 'X');
			a->Weird("SSH_max_string_length_exceeded", zeek::util::fmt("%u > %u", len, max_len));

			len = max_len;
		}

		return len;
		%}

	function proc_ssh_version_client(msg: SSH_Version_Client): bool
		%{
		if ( ssh_client_version )
			zeek::BifEvent::enqueue_ssh_client_version(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				to_stringval(${msg.version}));
		return true;
		%}

	function proc_ssh_version_server(msg: SSH_Version_Server): bool
		%{
		if ( ssh_server_version && ${msg.version}.length() > 0 )
			{
			zeek::BifEvent::enqueue_ssh_server_version(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				to_stringval(${msg.version}));
			}
		else if ( ssh_server_pre_banner_data )
			{
				zeek::BifEvent::enqueue_ssh_server_pre_banner_data(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(), to_stringval(${msg.nonversiondata}));
			}
		return true;
		%}

	function proc_ssh2_kexinit(msg: SSH2_KEXINIT): bool
		%{
		if ( ! ssh_capabilities )
			return false;

		auto result = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SSH::Capabilities);
		result->Assign(0, name_list_to_vector(${msg.kex_algorithms.val},
		                                      zeek::BifConst::SSH::max_kexinit_kex_algorithms,
		                                      "SSH_max_kexinit_kex_algorithms_exceeded",
		                                      connection()->zeek_analyzer()));

		result->Assign(1, name_list_to_vector(${msg.server_host_key_algorithms.val},
		                                      zeek::BifConst::SSH::max_kexinit_hostkey_algorithms,
		                                      "SSH_max_kexinit_hostkey_algorithms_exceeded",
		                                      connection()->zeek_analyzer()));


		auto encryption_algs = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SSH::Algorithm_Prefs);
		encryption_algs->Assign(0, name_list_to_vector(${msg.encryption_algorithms_client_to_server.val},
		                                               zeek::BifConst::SSH::max_kexinit_encryption_algorithms,
		                                               "SSH_max_kexinit_encryption_algorithms_exceeded",
		                                               connection()->zeek_analyzer()));
		encryption_algs->Assign(1, name_list_to_vector(${msg.encryption_algorithms_server_to_client.val},
		                                               zeek::BifConst::SSH::max_kexinit_encryption_algorithms,
		                                               "SSH_max_kexinit_encryption_algorithms_exceeded",
		                                               connection()->zeek_analyzer()));
		result->Assign(2, std::move(encryption_algs));

		auto mac_algs = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SSH::Algorithm_Prefs);
		mac_algs->Assign(0, name_list_to_vector(${msg.mac_algorithms_client_to_server.val},
		                                        zeek::BifConst::SSH::max_kexinit_mac_algorithms,
		                                        "SSH_max_kexinit_mac_algorithms_exceeded",
		                                        connection()->zeek_analyzer()));
		mac_algs->Assign(1, name_list_to_vector(${msg.mac_algorithms_server_to_client.val},
		                                        zeek::BifConst::SSH::max_kexinit_mac_algorithms,
		                                        "SSH_max_kexinit_mac_algorithms_exceeded",
		                                        connection()->zeek_analyzer()));
		result->Assign(3, std::move(mac_algs));

		auto compression_algs = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SSH::Algorithm_Prefs);
		compression_algs->Assign(0, name_list_to_vector(${msg.compression_algorithms_client_to_server.val},
		                                                zeek::BifConst::SSH::max_kexinit_compression_algorithms,
		                                                "SSH_max_kexinit_compression_algorithms_exceeded",
		                                                connection()->zeek_analyzer()));
		compression_algs->Assign(1, name_list_to_vector(${msg.compression_algorithms_server_to_client.val},
		                                                zeek::BifConst::SSH::max_kexinit_compression_algorithms,
		                                                "SSH_max_kexinit_compression_algorithms_exceeded",
		                                                connection()->zeek_analyzer()));
		result->Assign(4, std::move(compression_algs));

		if ( ${msg.languages_client_to_server.len} || ${msg.languages_server_to_client.len} )
			{
			auto languages = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::SSH::Algorithm_Prefs);
			if ( ${msg.languages_client_to_server.len} )
				languages->Assign(0, name_list_to_vector(${msg.languages_client_to_server.val},
		                                                         zeek::BifConst::SSH::max_kexinit_languages,
		                                                         "SSH_max_kexinit_languages_exceeded",
		                                                         connection()->zeek_analyzer()));
			if ( ${msg.languages_server_to_client.len} )
				languages->Assign(1, name_list_to_vector(${msg.languages_server_to_client.val},
		                                                         zeek::BifConst::SSH::max_kexinit_languages,
		                                                         "SSH_max_kexinit_languages_exceeded",
		                                                         connection()->zeek_analyzer()));
			result->Assign(5, std::move(languages));
			}


		result->Assign(6, !${msg.is_orig});

		zeek::BifEvent::enqueue_ssh_capabilities(connection()->zeek_analyzer(),
			connection()->zeek_analyzer()->Conn(), to_stringval(${msg.cookie}),
			result);

		return true;
		%}

	function proc_ssh2_ecc_init(is_orig: bool): bool
		%{
		if ( ssh2_ecc_init )
			{
			zeek::BifEvent::enqueue_ssh2_ecc_init(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig);
			}
		return true;
		%}

	function proc_ssh2_dh_gex_init(is_orig: bool): bool
		%{
		if ( ssh2_dh_gex_init )
			{
			zeek::BifEvent::enqueue_ssh2_dh_gex_init(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig);
			}
		return true;
		%}


	function proc_ssh2_gss_init(is_orig: bool): bool
		%{
		if ( ssh2_gss_init )
			{
			zeek::BifEvent::enqueue_ssh2_gss_init(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig);
			}
		return true;
		%}

	function proc_ssh2_rsa_secret(is_orig: bool): bool
		%{
		if ( ssh2_rsa_secret )
			{
			zeek::BifEvent::enqueue_ssh2_rsa_secret(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig);
			}
		return true;
		%}

	function proc_ssh2_dh_gex_group(msg: SSH2_DH_GEX_GROUP): bool
		%{
		if ( ssh2_dh_server_params )
			{
			zeek::BifEvent::enqueue_ssh2_dh_server_params(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				to_stringval(${msg.p.val}), to_stringval(${msg.g.val}));
			}
		return true;
		%}

	function proc_ssh2_ecc_key(q: bytestring, is_orig: bool): bool
		%{
		if ( ssh2_ecc_key )
			{
			zeek::BifEvent::enqueue_ssh2_ecc_key(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				is_orig, to_stringval(q));
			}
		return true;
		%}

	function proc_ssh2_gss_error(msg: SSH2_GSS_ERROR): bool
		%{
		if ( ssh2_gss_error )
			{
			zeek::BifEvent::enqueue_ssh2_gss_error(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				${msg.major_status}, ${msg.minor_status},
				to_stringval(${msg.message.val}));
			}
		return true;
		%}

	function proc_ssh2_server_host_key(key: bytestring): bool
		%{
		if ( ssh_server_host_key )
			{
			unsigned char digest[ZEEK_MD5_DIGEST_LENGTH];
			zeek::detail::internal_md5(${key}.data(), ${key}.length(), digest);

			zeek::BifEvent::enqueue_ssh_server_host_key(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				zeek::make_intrusive<zeek::StringVal>(fingerprint_md5(digest)));
			}

		if ( ssh2_server_host_key )
			{
			zeek::BifEvent::enqueue_ssh2_server_host_key(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				to_stringval(${key}));
			}

		return true;
		%}

	function proc_ssh1_server_host_key(exp: bytestring, mod: bytestring): bool
		%{
		if ( ssh_server_host_key )
			{
			unsigned char digest[ZEEK_MD5_DIGEST_LENGTH];
			auto ctx = zeek::detail::hash_init(zeek::detail::Hash_MD5);
			// Fingerprint is calculated over concatenation of modulus + exponent.
			zeek::detail::hash_update(ctx, ${mod}.data(), ${mod}.length());
			zeek::detail::hash_update(ctx, ${exp}.data(), ${exp}.length());
			zeek::detail::hash_final(ctx, digest);

			zeek::BifEvent::enqueue_ssh_server_host_key(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				zeek::make_intrusive<zeek::StringVal>(fingerprint_md5(digest)));
			}

		if ( ssh1_server_host_key )
			{
			zeek::BifEvent::enqueue_ssh1_server_host_key(connection()->zeek_analyzer(),
				connection()->zeek_analyzer()->Conn(),
				to_stringval(${mod}),
				to_stringval(${exp}));
			}

		return true;
		%}

	function proc_newkeys(): bool
		%{
		connection()->zeek_analyzer()->AnalyzerConfirmation();
		return true;
		%}

	function get_kex_length(v: int, packet_length: uint32): int
		%{
		switch (v) {
			case SSH1:
				return packet_length + 4 + 8 - (packet_length % 8);
			case SSH2:
				return packet_length + 4;
			default:
				return 1; //currently causes the rest of the packet to dump
		}
		%}
};

refine typeattr SSH_Version_Client += &let {
	proc: bool = $context.flow.proc_ssh_version_client(this);
};

refine typeattr SSH_Version_Server += &let {
	proc: bool = $context.flow.proc_ssh_version_server(this);
};

refine typeattr SSH2_KEXINIT += &let {
	proc: bool = $context.flow.proc_ssh2_kexinit(this);
};

refine typeattr SSH1_Message += &let {
	proc_newkeys: bool = $context.flow.proc_newkeys() &if(msg_type == SSH_CMSG_SESSION_KEY);
};

refine typeattr SSH2_Message += &let {
	proc_newkeys: bool = $context.flow.proc_newkeys() &if(msg_type == MSG_NEWKEYS);
};

refine typeattr SSH2_DH_GEX_REPLY += &let {
	proc: bool = $context.flow.proc_ssh2_server_host_key(k_s.val);
};

refine typeattr SSH2_GSS_HOSTKEY += &let {
	proc: bool = $context.flow.proc_ssh2_server_host_key(k_s.val);
};

refine typeattr SSH2_GSS_ERROR += &let {
	proc: bool = $context.flow.proc_ssh2_gss_error(this);
};

refine typeattr SSH2_DH_GEX_GROUP += &let {
	proc: bool = $context.flow.proc_ssh2_dh_gex_group(this);
};

refine typeattr SSH2_ECC_REPLY += &let {
	proc_k: bool = $context.flow.proc_ssh2_server_host_key(k_s.val);
	proc_q: bool = $context.flow.proc_ssh2_ecc_key(q_s.val, is_orig);
};

refine typeattr SSH2_ECC_INIT += &let {
	proc: bool = $context.flow.proc_ssh2_ecc_key(q_c.val, is_orig);
	proc_init: bool = $context.flow.proc_ssh2_ecc_init(is_orig);
};

refine typeattr SSH2_DH_GEX_INIT += &let {
	proc_init: bool = $context.flow.proc_ssh2_dh_gex_init(is_orig);
};

refine typeattr SSH2_GSS_INIT += &let {
	proc_init: bool = $context.flow.proc_ssh2_gss_init(is_orig);
};

refine typeattr SSH2_RSA_SECRET += &let {
	proc_init: bool = $context.flow.proc_ssh2_rsa_secret(is_orig);
};

refine typeattr SSH1_PUBLIC_KEY += &let {
	proc:  bool = $context.flow.proc_ssh1_server_host_key(host_key_exp.val, host_key_mod.val);
};
