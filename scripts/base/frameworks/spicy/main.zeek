@load base/frameworks/notice

module Spicy;

export {
    redef enum Notice::Type += { Spicy_Max_File_Depth_Exceeded };
}

event max_file_depth_exceeded(f: fa_file, args: Files::AnalyzerArgs, limit: count)
    {
    NOTICE([
            $note=Spicy::Spicy_Max_File_Depth_Exceeded,
            $msg=fmt("Maximum file depth exceeded for file %s", f$id)
    ]);
    }
