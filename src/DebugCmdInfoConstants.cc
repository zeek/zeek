
//
// This file was automatically generated from ./DebugCmdInfoConstants.in
// DO NOT EDIT.
//

#include "util.h"
void init_global_dbg_constants () {

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	
      };

      info = new DebugCmdInfo (dcInvalid, names, 0, false, "This function should not be called",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"help"
      };

      info = new DebugCmdInfo (dcHelp, names, 1, false, "Get help with debugger commands",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"quit"
      };

      info = new DebugCmdInfo (dcQuit, names, 1, false, "Exit Bro",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"next"
      };

      info = new DebugCmdInfo (dcNext, names, 1, true, "Step to the following statement, skipping function calls",
                               true);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"step",
	"s"
      };

      info = new DebugCmdInfo (dcStep, names, 2, true, "Step to following statements, stepping in to function calls",
                               true);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"continue",
	"c"
      };

      info = new DebugCmdInfo (dcContinue, names, 2, true, "Resume execution of the policy script",
                               true);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"finish"
      };

      info = new DebugCmdInfo (dcFinish, names, 1, true, "Run until the currently-executing function completes",
                               true);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"break",
	"b"
      };

      info = new DebugCmdInfo (dcBreak, names, 2, false, "Set a breakpoint",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"cond"
      };

      info = new DebugCmdInfo (dcBreakCondition, names, 1, false, "",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"delete",
	"d"
      };

      info = new DebugCmdInfo (dcDeleteBreak, names, 2, false, "Delete the specified breakpoints; delete all if no arguments",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"clear"
      };

      info = new DebugCmdInfo (dcClearBreak, names, 1, false, "",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"disable",
	"dis"
      };

      info = new DebugCmdInfo (dcDisableBreak, names, 2, false, "",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"enable"
      };

      info = new DebugCmdInfo (dcEnableBreak, names, 1, false, "",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"ignore"
      };

      info = new DebugCmdInfo (dcIgnoreBreak, names, 1, false, "",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"print",
	"p",
	"set"
      };

      info = new DebugCmdInfo (dcPrint, names, 3, false, "Evaluate an expression and print the result (also aliased as 'set')",
                               true);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"backtrace",
	"bt",
	"where"
      };

      info = new DebugCmdInfo (dcBacktrace, names, 3, false, "Print a stack trace (with +- N argument, inner/outer N frames only)",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"frame"
      };

      info = new DebugCmdInfo (dcFrame, names, 1, false, "Select frame number N",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"up"
      };

      info = new DebugCmdInfo (dcUp, names, 1, false, "Select the stack frame one level up",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"down"
      };

      info = new DebugCmdInfo (dcDown, names, 1, false, "Select the stack frame one level down",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"info"
      };

      info = new DebugCmdInfo (dcInfo, names, 1, false, "Get information about the debugging environment",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"list",
	"l"
      };

      info = new DebugCmdInfo (dcList, names, 2, false, "Print source lines surrounding specified context",
                               true);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"display"
      };

      info = new DebugCmdInfo (dcDisplay, names, 1, false, "",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"undisplay"
      };

      info = new DebugCmdInfo (dcUndisplay, names, 1, false, "",
                               false);
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"trace"
      };

      info = new DebugCmdInfo (dcTrace, names, 1, false, "Turn on or off execution tracing (with no arguments, prints current state.)",
                               false);
      g_DebugCmdInfos.push_back(info);
   }
   
}
