%extern{
#include "../dce-rpc/DCE_RPC.h"
%}

refine connection SMB_Conn += {
	%member{
		map<uint16,bool> tree_is_pipe_map;
		map<uint64,analyzer::dce_rpc::DCE_RPC_Analyzer*> fid_to_analyzer_map;;
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


	function get_tree_is_pipe(tree_id: uint16): bool
		%{
		if ( tree_is_pipe_map.count(tree_id) > 0 )
			return tree_is_pipe_map.at(tree_id);
		else
			return false;
		%}

	function set_tree_is_pipe(tree_id: uint16, is_pipe: bool): bool
		%{
		tree_is_pipe_map[tree_id] = is_pipe;
		return true;
		%}

	function forward_dce_rpc(pipe_data: bytestring, fid: uint64, is_orig: bool): bool
		%{
		analyzer::dce_rpc::DCE_RPC_Analyzer *pipe_dcerpc;
		if ( fid_to_analyzer_map.count(fid) == 0 )
			{
			pipe_dcerpc = (analyzer::dce_rpc::DCE_RPC_Analyzer *)analyzer_mgr->InstantiateAnalyzer("DCE_RPC", bro_analyzer()->Conn());
			pipe_dcerpc->SetFileID(fid);
			fid_to_analyzer_map[fid] = pipe_dcerpc;
			}
		else
			{
			pipe_dcerpc = fid_to_analyzer_map.at(fid);
			}

		pipe_dcerpc->DeliverStream(${pipe_data}.length(), ${pipe_data}.begin(), is_orig);

		return true;
		%}
};
