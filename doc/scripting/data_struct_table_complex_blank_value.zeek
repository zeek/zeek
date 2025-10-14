event zeek_init()
    {
    # local samurai_flicks: ...

    for ( [d, _, _, _], name in samurai_flicks )
        print fmt("%s was directed by %s", name, d);

    for ( _, name in samurai_flicks )
        print fmt("%s is a movie", name);
    }

