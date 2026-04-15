##! Provides basic connection functionality for working with the XDP
##! shunter. Most users should not need to use anything within this
##! file, it is a more low-level API to interact with the XDP program
##! itself.

@ifdef ( XDP::__load_and_attach )
module XDP;

export {
	## Reuses an already-existing XDP shunting program's maps.
	## This allows Zeek to add and remove from the map.
	##
	## Reusing is preferable to load_and_attach in all but standalone
	## instances of Zeek.
	##
	## Returns: An opaque value representing the now-attached BPF program
	##
	## .. zeek:see:: load_and_attach
	global reuse_maps: function(options: XDP::ShuntOptions): bool;

	## Releases the XDP program maps without unloading it.
	global release_maps: function();

	## Begins shunting with XDP by loading the XDP program and necessary BPF maps.
	##
	## Returns: An opaque value representing the now-attached BPF program
	##
	## .. zeek:see:: detach
	global load_and_attach: function(options: XDP::ShuntOptions): bool;

	## Stops the XDP shunting program.
	##
	## Returns: Whether the operation succeeded
	##
	## .. zeek:see:: load_and_attach
	global detach: function(): bool;

	## Transforms a conn_id into its canonical_id representation
	## by sorting the IPs and ports as the shunting map does.
	global conn_id_to_canonical: function(cid: conn_id): XDP::canonical_id;

	## The handle for the XDP program, used internally for any
	## operations pertaining to it or its maps.
	global xdp_prog: opaque of XDP::Program;

	## Whether or not vlans should be included. This is necessary to
	## construct the correct "canonical" tuple for the XDP program.
	global vlans_included: bool;

	## This hook is checked when shunting a connection in order to provide
	## users a mechanism to veto a shunting decision. Simply break from the
	## hook to prevent shunting a connection.
	global shunting: hook(c: connection);
}

function reuse_maps(options: XDP::ShuntOptions): bool
	{
	xdp_prog = __reuse_maps(options);
	# TODO: if it fails this should probably return F
	return T;
	}

function release_maps()
	{
	__release_maps(xdp_prog);
	}

function load_and_attach(options: XDP::ShuntOptions): bool
	{
	xdp_prog = __load_and_attach(options);
	# TODO: if it fails this should probably return F
	return T;
	}

function detach(): bool
	{
	return __detach(xdp_prog);
	}

function conn_id_to_canonical(cid: conn_id): XDP::canonical_id
	{
	return __conn_id_to_canonical(cid, XDP::vlans_included);
	}

@endif
