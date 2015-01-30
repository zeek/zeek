event bro_init()
    {
    local filter: Log::Filter =
        [
        $name="sqlite",
        $path="/var/db/conn",
        $config=table(["tablename"] = "conn"),
        $writer=Log::WRITER_SQLITE
        ];
    
     Log::add_filter(Conn::LOG, filter);
    }
