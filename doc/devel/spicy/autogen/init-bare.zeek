
module Spicy;

export {
# doc-options-start
    ## Constant for testing if Spicy is available.
    const available = T;

    ## Show output of Spicy print statements.
    const enable_print = F &redef;

    # Record and display profiling information, if compiled into analyzer.
    const enable_profiling = F &redef;

    ## abort() instead of throwing HILTI exceptions.
    const abort_on_exceptions = F &redef;

    ## Include backtraces when reporting unhandled exceptions.
    const show_backtraces = F &redef;

    ## Maximum depth of recursive file analysis (Spicy analyzers only)
    const max_file_depth: count = 5 &redef;
# doc-options-end

# doc-types-start
    ## Result type for `Spicy::resource_usage()`. The values reflect resource
    ## usage as reported by the Spicy runtime system.
    type ResourceUsage: record {
        user_time : interval;           ##< user CPU time of the Zeek process
        system_time :interval;          ##< system CPU time of the Zeek process
        memory_heap : count;            ##< memory allocated on the heap by the Zeek process
        num_fibers : count;             ##< number of fibers currently in use
        max_fibers: count;              ##< maximum number of fibers ever in use
        max_fiber_stack_size: count;    ##< maximum fiber stack size ever in use
        cached_fibers: count;           ##< number of fibers currently cached
    };
# doc-types-end
}
