##! Interface for the None log writer. This writer is mainly for debugging.

module LogNone;

export {
	## If true, output debugging output that can be useful for unit
        ## testing the logging framework.
	const debug = F &redef;
}

function default_rotation_postprocessor_func(info: Log::RotationInfo) : bool
	{
	return T;
	}

redef Log::default_rotation_postprocessors += { [Log::WRITER_NONE] = default_rotation_postprocessor_func };

