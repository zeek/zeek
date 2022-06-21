##! This module provides functionality the Management framework places directly
##! in the Supervisor.

@load base/utils/paths
@load base/utils/queue

@load policy/frameworks/management/types
@load policy/frameworks/management/node/config

@load ./api
@load ./config

module Management::Supervisor;

# stdout/stderr state for a given node.
type NodeOutputStreams: record {
	# Line buffers for stdout and stderr. Their length is capped
	# to the most recent Management::Supervisor::output_max_lines.
	stdout: Queue::Queue;
	stderr: Queue::Queue;

	#
	stdout_file: file &optional;
	stderr_file: file &optional;
};

# This tracks output state for the current nodes.
global g_outputs: table[string] of NodeOutputStreams;

function make_node_output_streams(node: string): NodeOutputStreams
	{
	local stdout = Queue::init([$max_len = Management::Supervisor::output_max_lines]);
	local stderr = Queue::init([$max_len = Management::Supervisor::output_max_lines]);

	local res = NodeOutputStreams($stdout=stdout, $stderr=stderr);
	local status = Supervisor::status(node);

	if ( node !in status$nodes )
		return res;

	local ns = status$nodes[node];
	local directory = ".";

	if ( ns$node?$directory )
		directory = ns$node$directory;

	if ( Management::Node::stdout_file != "" )
		res$stdout_file = open(build_path(directory, Management::Node::stdout_file));
	if ( Management::Node::stderr_file != "" )
		res$stderr_file = open(build_path(directory, Management::Node::stderr_file));

	return res;
	}

hook Supervisor::stdout_hook(node: string, msg: string)
	{
	if ( node !in g_outputs )
		g_outputs[node] = make_node_output_streams(node);

	# Write to the stdout file if we have one. The flush is clunky, but
	# seems worth it: it's too confusing for errors to have happened and not
	# yet shown up in the file. (The Supervisor's built-in file redirection
	# does this too.)
	if ( g_outputs[node]?$stdout_file )
		{
		print g_outputs[node]$stdout_file, msg;
		flush_all();
		}

	# Update the sliding window of recent output lines.
	Queue::put(g_outputs[node]$stdout, msg);

	if ( ! print_stdout )
		break;
	}

hook Supervisor::stderr_hook(node: string, msg: string)
	{
	if ( node !in g_outputs )
		g_outputs[node] = make_node_output_streams(node);

	if ( g_outputs[node]?$stderr_file )
		{
		print g_outputs[node]$stderr_file, msg;
		flush_all();
		}

	Queue::put(g_outputs[node]$stderr, msg);

	if ( ! print_stderr )
		break;
	}

event Supervisor::node_status(node: string, pid: count)
	{
	# The node just started or restarted. If we have collected any output
	# for its past life, send it via a notify_node_exit event.
	if ( node in g_outputs )
		{
		local stdout_lines: vector of string;
		local stderr_lines: vector of string;

		Queue::get_vector(g_outputs[node]$stdout, stdout_lines);
		Queue::get_vector(g_outputs[node]$stderr, stderr_lines);

		if ( |stdout_lines| > 0 || |stderr_lines| > 0 )
			{
			local outputs = Management::NodeOutputs(
			    $stdout = join_string_vec(stdout_lines, "\n"),
			    $stderr = join_string_vec(stderr_lines, "\n"));

			Broker::publish(topic_prefix, Management::Supervisor::API::notify_node_exit, node, outputs);
			}

		if ( g_outputs[node]?$stdout_file )
			close(g_outputs[node]$stdout_file);
		if ( g_outputs[node]?$stderr_file )
			close(g_outputs[node]$stderr_file);
		}

	g_outputs[node] = make_node_output_streams(node);
	}
