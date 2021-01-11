void InitGlobalDbgConstants () {
   {

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"help"
      };

      info = new DebugCmdInfo (dcHelp, names, 1, false, "Get help with debugger commands");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"quit"
      };

      info = new DebugCmdInfo (dcQuit, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"next"
      };

      info = new DebugCmdInfo (dcNext, names, 1, true, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"step"
      };

      info = new DebugCmdInfo (dcStep, names, 1, true, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"continue"
      };

      info = new DebugCmdInfo (dcContinue, names, 1, true, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"finish"
      };

      info = new DebugCmdInfo (dcFinish, names, 1, true, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"break"
      };

      info = new DebugCmdInfo (dcBreak, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"cond"
      };

      info = new DebugCmdInfo (dcBreakCondition, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"delete"
      };

      info = new DebugCmdInfo (dcDeleteBreak, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"clear"
      };

      info = new DebugCmdInfo (dcClearBreak, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"disable"
      };

      info = new DebugCmdInfo (dcDisableBreak, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"enable"
      };

      info = new DebugCmdInfo (dcEnableBreak, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"ignore"
      };

      info = new DebugCmdInfo (dcIgnoreBreak, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"print"
      };

      info = new DebugCmdInfo (dcPrint, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"backtrace",
	"bt"
      };

      info = new DebugCmdInfo (dcBacktrace, names, 2, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"frame"
      };

      info = new DebugCmdInfo (dcFrame, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"info"
      };

      info = new DebugCmdInfo (dcInfo, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"list"
      };

      info = new DebugCmdInfo (dcList, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"display"
      };

      info = new DebugCmdInfo (dcDisplay, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

   {
      DebugCmdInfo* info;
      const char * const names[] = {
	"undisplay"
      };

      info = new DebugCmdInfo (dcUndisplay, names, 1, false, "");
      g_DebugCmdInfos.push_back(info);
   }

}
