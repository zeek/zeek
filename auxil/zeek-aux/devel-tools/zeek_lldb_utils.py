import lldb
from ansi.color import fg
from ansi.color.fx import reset
from linereader import getline

# Cache script lines and files so that we don't have to load files repeatedly
script_lines = {}

# TODO: make this check that the thread is actually stopped and return an error if not


@lldb.command("btz")
def backtrace_zeek(debugger, command, exe_ctx, result, d):
    selected_thread = exe_ctx.GetProcess().GetSelectedThread()
    thread = exe_ctx.GetThread()

    # I'd prefer to retrieve this from LLDB somehow, but the earlier versions
    # don't have SDDebugger.GetSetting(), and I'm not really sure we could use
    # the output from that anyways.
    thread_format = f"{'*' if selected_thread.idx == thread.idx else ' '} thread #{thread.idx}, name = '{thread.name}', queue = {fg.green}'{thread.queue}'{reset}, stop reason = {fg.red}{thread.GetStopDescription(100)}{reset}"
    print(thread_format)

    selected_frame = thread.GetSelectedFrame().idx

    for frame in thread.get_thread_frames():
        frame_output = f"  {'*' if frame.idx == selected_frame else ' '} "
        frame_output += f"{frame}"

        this = frame.FindVariable("this")
        if this:
            loc_ptr = this.GetChildMemberWithName("location")
            if loc_ptr and loc_ptr.GetType().GetName() == "zeek::detail::Location *":
                if loc_ptr.GetValueAsUnsigned() != 0:
                    loc = frame.EvaluateExpression("*(this->location)")
                    fname = (
                        loc.GetChildMemberWithName("filename").GetSummary().strip('"')
                    )
                    line_no = loc.GetChildMemberWithName(
                        "first_line"
                    ).GetValueAsUnsigned()
                    frame_output += f"\n        {fg.green}zeek script:{reset} {fname}"

                    fileinfo = f"{fname}:{line_no}"
                    if fileinfo in script_lines:
                        line = script_lines[fileinfo]
                    else:
                        line = getline(fname, line_no)
                        line = line.strip()
                        script_lines[fileinfo] = line

                    if line:
                        line_hdr = f"line {line_no}"
                        frame_output += (
                            f"\n        {fg.green}{line_hdr: >11}:{reset} {line}"
                        )

        print(frame_output)
