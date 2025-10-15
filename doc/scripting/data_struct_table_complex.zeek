event zeek_init()
    {
    local samurai_flicks: table[string, string, count, string] of string;
    
    samurai_flicks["Kihachi Okamoto", "Toho", 1968, "Tatsuya Nakadai"] = "Kiru";
    samurai_flicks["Hideo Gosha", "Fuji", 1969, "Tatsuya Nakadai"] = "Goyokin";
    samurai_flicks["Masaki Kobayashi", "Shochiku Eiga", 1962, "Tatsuya Nakadai" ] = "Harakiri";
    samurai_flicks["Yoji Yamada", "Eisei Gekijo", 2002, "Hiroyuki Sanada" ] = "Tasogare Seibei";
    
    for ( [d, s, y, a] in samurai_flicks )
        print fmt("%s was released in %d by %s studios, directed by %s and starring %s", samurai_flicks[d, s, y, a], y, s, d, a);
    }

