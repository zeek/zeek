%extern{
#include "../dce-rpc/DCE_RPC.h"
%}

refine connection SMB_Conn += {
	%member{
		map<uint32,bool> tree_is_pipe_map;
		map<uint64,analyzer::dce_rpc::DCE_RPC_Analyzer*> fid_to_analyzer_map;
	%}

	%cleanup{
		// Iterate all of the analyzers and destroy them.
		for ( auto kv : fid_to_analyzer_map )
			{
			if ( kv.second )
				{
				kv.second->Done();
				delete kv.second;
				}
			}
	%}

	function get_tree_is_pipe(tree_id: uint32): bool
		%{
		return ( tree_is_pipe_map.count(tree_id) > 0 && tree_is_pipe_map.at(tree_id) );
		%}

	function unset_tree_is_pipe(tree_id: uint32): bool
		%{
		tree_is_pipe_map.erase(tree_id);
		return true;
		%}

	function set_tree_is_pipe(tree_id: uint32): bool
		%{
		tree_is_pipe_map[tree_id] = true;
		return true;
		%}

	function forward_dce_rpc(pipe_data: bytestring, fid: uint64, is_orig: bool): bool
		%{
		analyzer::dce_rpc::DCE_RPC_Analyzer *pipe_dcerpc = nullptr;
		if ( fid_to_analyzer_map.count(fid) == 0 )
			{
			auto tmp_analyzer = analyzer_mgr->InstantiateAnalyzer("DCE_RPC", bro_analyzer()->Conn());
			pipe_dcerpc = static_cast<analyzer::dce_rpc::DCE_RPC_Analyzer *>(tmp_analyzer);
			if ( pipe_dcerpc )
				{
				pipe_dcerpc->SetFileID(fid);
				fid_to_analyzer_map[fid] = pipe_dcerpc;
				}
			}
		else
			{
			pipe_dcerpc = fid_to_analyzer_map.at(fid);
			}

		if ( pipe_dcerpc )
			pipe_dcerpc->DeliverStream(${pipe_data}.length(), ${pipe_data}.begin(), is_orig);

		return true;
		%}
};
