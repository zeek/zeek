##! The summary statistics framework provides a way to
##! summarize large streams of data into simple reduced
##! measurements.

module SumStats;

export {
	## The various calculations are all defined as plugins.
	type Calculation: enum {
		PLACEHOLDER
	};

	## Represents a thing which is having summarization
	## results collected for it.
	type Key: record {
		## A non-address related summarization or a sub-key for
		## an address based summarization. An example might be
		## successful SSH connections by client IP address
		## where the client string would be the key value.
		## Another example might be number of HTTP requests to
		## a particular value in a Host header.  This is an
		## example of a non-host based metric since multiple
		## IP addresses could respond for the same Host
		## header value.
		str:  string &optional;

		## Host is the value to which this metric applies.
		host: addr &optional;
	};

	## Represents data being added for a single observation.
	## Only supply a single field at a time!
	type Observation: record {
		## Count value.
		num:  count  &optional;
		## Double value.
		dbl:  double &optional;
		## String value.
		str:  string &optional;
	};

	type Reducer: record {
		## Observation stream identifier for the reducer
		## to attach to.
		stream:         string;

		## The calculations to perform on the data points.
		apply:          set[Calculation];

		## A predicate so that you can decide per key if you
		## would like to accept the data being inserted.
		pred:           function(key: SumStats::Key, obs: SumStats::Observation): bool &optional;

		## A function to normalize the key.  This can be used to
		## aggregate or normalize the entire key.
		normalize_key:  function(key: SumStats::Key): Key &optional;
	};

	## Value calculated for an observation stream fed into a reducer.
	## Most of the fields are added by plugins.
	type ResultVal: record {
		## The time when the first observation was added to
		## this result value.
		begin:  time;

		## The time when the last observation was added to
		## this result value.
		end:    time;

		## The number of observations received.
		num:    count &default=0;
	};

	## Type to store results for multiple reducers.
	type Result: table[string] of ResultVal;

	## Type to store a table of sumstats results indexed by keys.
	type ResultTable: table[Key] of Result;

	## SumStats represent an aggregation of reducers along with
	## mechanisms to handle various situations like the epoch ending
	## or thresholds being crossed.
	##
	## It's best to not access any global state outside
	## of the variables given to the callbacks because there
	## is no assurance provided as to where the callbacks
	## will be executed on clusters.
	type SumStat: record {
		## An arbitrary name for the sumstat so that it can 
		## be referred to later.
		name:               string;
		
		## The interval at which this filter should be "broken"
		## and the *epoch_result* callback called.  The
		## results are also reset at this time so any threshold
		## based detection needs to be set to a
		## value that should be expected to happen within
		## this epoch.
		epoch:              interval;

		## The reducers for the SumStat.
		reducers:           set[Reducer];

		## Provide a function to calculate a value from the
		## :bro:see:`SumStats::Result` structure which will be used
		## for thresholding.
		## This is required if a *threshold* value is given.
		threshold_val:      function(key: SumStats::Key, result: SumStats::Result): double &optional;

		## The threshold value for calling the
		## *threshold_crossed* callback.
		threshold:          double            &optional;

		## A series of thresholds for calling the
		## *threshold_crossed* callback.
		threshold_series:   vector of double  &optional;

		## A callback that is called when a threshold is crossed.
		threshold_crossed:  function(key: SumStats::Key, result: SumStats::Result) &optional;

		## A callback that receives each of the results at the
		## end of the analysis epoch.  The function will be 
		## called once for each key.
		epoch_result:       function(ts: time, key: SumStats::Key, result: SumStats::Result) &optional;
	
		## A callback that will be called when a single collection 
		## interval is completed.  The *ts* value will be the time of 
		## when the collection started.
		epoch_finished:     function(ts:time) &optional;
	};

	## Create a summary statistic.
	global create: function(ss: SumStats::SumStat);

	## Add data into an observation stream. This should be
	## called when a script has measured some point value.
	##
	## id: The observation stream identifier that the data
	##     point represents.
	##
	## key: The key that the value is related to.
	##
	## obs: The data point to send into the stream.
	global observe: function(id: string, key: SumStats::Key, obs: SumStats::Observation);

	## Dynamically request a sumstat key.  This function should be
	## used sparingly and not as a replacement for the callbacks 
	## from the :bro:see:`SumStats::SumStat` record.  The function is only
	## available for use within "when" statements as an asynchronous
	## function.
	##
	## ss_name: SumStat name.
	##
	## key: The SumStat key being requested.
	##
	## Returns: The result for the requested sumstat key.
	global request_key: function(ss_name: string, key: Key): Result;

	## Helper function to represent a :bro:type:`SumStats::Key` value as
	## a simple string.
	##
	## key: The metric key that is to be converted into a string.
	##
	## Returns: A string representation of the metric key.
	global key2str: function(key: SumStats::Key): string;
}

# The function prototype for plugins to do calculations.
type ObserveFunc: function(r: Reducer, val: double, data: Observation, rv: ResultVal);

redef record Reducer += {
	# Internal use only.  Provides a reference back to the related SumStats by its name.
	ssname: string &optional;

	calc_funcs: vector of Calculation &optional;
};

# Internal use only.  For tracking thresholds per sumstat and key.
# In the case of a single threshold, 0 means the threshold isn't crossed.
# In the case of a threshold series, the number tracks the threshold offset.
global threshold_tracker: table[string] of table[Key] of count;

function increment_threshold_tracker(ss_name: string, key: Key)
	{
	if ( ss_name !in threshold_tracker )
		threshold_tracker[ss_name] = table();
	if ( key !in threshold_tracker[ss_name] )
		threshold_tracker[ss_name][key] = 0;

	++threshold_tracker[ss_name][key];
	}

function get_threshold_index(ss_name: string, key: Key): count
	{
	if ( ss_name !in threshold_tracker )
		return 0;
	if ( key !in threshold_tracker[ss_name] )
		return 0;

	return threshold_tracker[ss_name][key];
	}

# Prototype the hook point for plugins to initialize any result values.
global init_resultval_hook: hook(r: Reducer, rv: ResultVal);

# Prototype the hook point for plugins to merge Results.
global compose_resultvals_hook: hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal);

# Store of sumstats indexed on the sumstat id.
global stats_store: table[string] of SumStat = table();

# Store of reducers indexed on the data point stream id.
global reducer_store: table[string] of set[Reducer] = table();

# Store of results indexed on the measurement id.
global result_store: table[string] of ResultTable = table();

# Store of threshold information.
global thresholds_store: table[string, Key] of bool = table();

# Store the calculations.
global calc_store: table[Calculation] of ObserveFunc = table();

# Store the dependencies for Calculations.
global calc_deps: table[Calculation] of vector of Calculation = table();

# Hook for registering observation calculation plugins.
global register_observe_plugins: hook();

# This is called whenever key values are updated and the new val is given as the
# `val` argument. It's only prototyped here because cluster and non-cluster have
# separate  implementations.
global data_added: function(ss: SumStat, key: Key, result: Result);

# Event that is used to "finish" measurements and adapt the measurement
# framework for clustered or non-clustered usage.
global finish_epoch: event(ss: SumStat);

function key2str(key: Key): string
	{
	local out = "";
	if ( key?$host )
		out = fmt("%shost=%s", out, key$host);
	if ( key?$str )
		out = fmt("%s%sstr=%s", out, |out|==0 ? "" : ", ", key$str);
	return fmt("sumstats_key(%s)", out);
	}

function register_observe_plugin(calc: Calculation, func: ObserveFunc)
	{
	calc_store[calc] = func;
	}

function add_observe_plugin_dependency(calc: Calculation, depends_on: Calculation)
	{
	if ( calc !in calc_deps )
		calc_deps[calc] = vector();
	calc_deps[calc][|calc_deps[calc]|] = depends_on;
	}

event bro_init() &priority=100000
	{
	# Call all of the plugin registration hooks
	hook register_observe_plugins();
	}

function init_resultval(r: Reducer): ResultVal
	{
	local rv: ResultVal = [$begin=network_time(), $end=network_time()];
	hook init_resultval_hook(r, rv);
	return rv;
	}

function compose_resultvals(rv1: ResultVal, rv2: ResultVal): ResultVal
	{
	local result: ResultVal;

	result$begin = (rv1$begin < rv2$begin) ? rv1$begin : rv2$begin;
	result$end = (rv1$end > rv2$end) ? rv1$end : rv2$end;
	result$num = rv1$num + rv2$num;

	# Run the plugin composition hooks.
	hook compose_resultvals_hook(result, rv1, rv2);
	return result;
	}

function compose_results(r1: Result, r2: Result): Result
	{
	local result: Result = table();

	for ( id in r1 )
		{
		result[id] = r1[id];
		}

	for ( id in r2 )
		{
		if ( id in r1 )
			result[id] = compose_resultvals(r1[id], r2[id]);
		else
			result[id] = r2[id];
		}

	return result;
	}


function reset(ss: SumStat)
	{
	if ( ss$name in result_store )
		delete result_store[ss$name];

	result_store[ss$name] = table();

	if ( ss$name in threshold_tracker )
		{
		delete threshold_tracker[ss$name];
		threshold_tracker[ss$name] = table();
		}
	}

# This could potentially recurse forever, but plugin authors 
# should be making sure they aren't causing reflexive dependencies.
function add_calc_deps(calcs: vector of Calculation, c: Calculation)
	{
	#print fmt("Checking for deps for %s", c);
	for ( i in calc_deps[c] )
		{
		local skip_calc=F;
		for ( j in calcs )
			{
			if ( calcs[j] == calc_deps[c][i] )
				skip_calc=T;
			}
		if ( ! skip_calc )
			{
			if ( calc_deps[c][i] in calc_deps )
				add_calc_deps(calcs, calc_deps[c][i]);
			calcs[|c|] = calc_deps[c][i];
			#print fmt("add dep for %s [%s] ", c, calc_deps[c][i]);
			}
		}

	}

function create(ss: SumStat)
	{
	if ( (ss?$threshold || ss?$threshold_series) && ! ss?$threshold_val )
		{
		Reporter::error("SumStats given a threshold with no $threshold_val function");
		}

	stats_store[ss$name] = ss;

	if ( ss?$threshold || ss?$threshold_series )
		threshold_tracker[ss$name] = table();

	for ( reducer in ss$reducers )
		{
		reducer$ssname = ss$name;
		reducer$calc_funcs = vector();
		for ( calc in reducer$apply )
			{
			# Add in dependencies recursively.
			if ( calc in calc_deps )
				add_calc_deps(reducer$calc_funcs, calc);

			# Don't add this calculation to the vector if 
			# it was already added by something else as a 
			# dependency.
			local skip_calc=F;
			for ( j in reducer$calc_funcs )
				{
				if ( calc == reducer$calc_funcs[j] )
					skip_calc=T;
				}
			if ( ! skip_calc )
				reducer$calc_funcs[|reducer$calc_funcs|] = calc;
			}

		if ( reducer$stream !in reducer_store )
			reducer_store[reducer$stream] = set();
		add reducer_store[reducer$stream][reducer];
		}

	reset(ss);
	schedule ss$epoch { SumStats::finish_epoch(ss) };
	}

function observe(id: string, key: Key, obs: Observation)
	{
	if ( id !in reducer_store )
		return;

	# Try to add the data to all of the defined reducers.
	for ( r in reducer_store[id] )
		{
		if ( r?$normalize_key )
			key = r$normalize_key(copy(key));

		# If this reducer has a predicate, run the predicate
		# and skip this key if the predicate return false.
		if ( r?$pred && ! r$pred(key, obs) )
			next;

		local ss = stats_store[r$ssname];

		# If there is a threshold and no epoch_result callback
		# we don't need to continue counting since the data will
		# never be accessed.  This was leading
		# to some state management issues when measuring
		# uniqueness.
		# NOTE: this optimization could need removed in the
		#       future if on demand access is provided to the
		#       SumStats results.
		if ( ! ss?$epoch_result &&
			 r$ssname in threshold_tracker &&
		     ( ss?$threshold &&
		       key in threshold_tracker[r$ssname] &&
		       threshold_tracker[r$ssname][key] != 0 ) ||
		     ( ss?$threshold_series &&
		       key in threshold_tracker[r$ssname] &&
		       threshold_tracker[r$ssname][key] == |ss$threshold_series| ) )
			{
			next;
			}

		if ( r$ssname !in result_store )
			result_store[r$ssname] = table();
		local results = result_store[r$ssname];

		if ( key !in results )
			results[key] = table();
		local result = results[key];

		if ( id !in result )
			result[id] = init_resultval(r);
		local result_val = result[id];

		++result_val$num;
		# Continually update the $end field.
		result_val$end=network_time();

		# If a string was given, fall back to 1.0 as the value.
		local val = 1.0;
		if ( obs?$num )
			val = obs$num;
		else if ( obs?$dbl )
			val = obs$dbl;

		for ( i in r$calc_funcs )
			calc_store[r$calc_funcs[i]](r, val, obs, result_val);
		data_added(ss, key, result);
		}
	}

# This function checks if a threshold has been crossed.  It is also used as a method to implement
# mid-break-interval threshold crossing detection for cluster deployments.
function check_thresholds(ss: SumStat, key: Key, result: Result, modify_pct: double): bool
	{
	if ( ! (ss?$threshold || ss?$threshold_series || ss?$threshold_crossed) )
		return F;

	# Add in the extra ResultVals to make threshold_vals easier to write.
	# This length comparison should work because we just need to make 
	# sure that we have the same number of reducers and results.
	if ( |ss$reducers| != |result| )
		{
		for ( reducer in ss$reducers )
			{
			if ( reducer$stream !in result )
				result[reducer$stream] = init_resultval(reducer);
			}
		}

	local watch = ss$threshold_val(key, result);

	if ( modify_pct < 1.0 && modify_pct > 0.0 )
		watch = watch/modify_pct;

	local t_index = get_threshold_index(ss$name, key);

	if ( ss?$threshold &&
	     t_index == 0 && # Check that the threshold hasn't already been crossed.
	     watch >= ss$threshold )
		{
		# Value crossed the threshold.
		return T;
		}

	if ( ss?$threshold_series &&
	     |ss$threshold_series| > t_index && # Check if there are more thresholds.
	     watch >= ss$threshold_series[t_index] )
		{
		# A threshold series was given and the value crossed the next
		# value in the series.
		return T;
		}

	return F;
	}

function threshold_crossed(ss: SumStat, key: Key, result: Result)
	{
	# If there is no callback, there is no point in any of this.
	if ( ! ss?$threshold_crossed )
		return;

	increment_threshold_tracker(ss$name,key);

	# Add in the extra ResultVals to make threshold_crossed callbacks easier to write.
	if ( |ss$reducers| != |result| )
		{
		for ( reducer in ss$reducers )
			{
			if ( reducer$stream !in result )
				result[reducer$stream] = init_resultval(reducer);
			}
		}

	ss$threshold_crossed(key, result);
	}

