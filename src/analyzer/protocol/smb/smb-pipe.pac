
refine connection SMB_Conn += {
	%member{
		map<uint16,bool> tree_is_pipe_map;
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

	function forward_dce_rpc(pipe_data: bytestring, is_orig: bool): bool
		%{
		if ( dcerpc )
			dcerpc->DeliverStream(${pipe_data}.length(), ${pipe_data}.begin(), is_orig);
		return true;
		%}
};