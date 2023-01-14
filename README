=================================
The Zeek Network Security Monitor
=================================

Zeek is a powerful framework for network traffic analysis and security
monitoring. Follow us on Twitter at @zeekurity.

Key Features
============

*   **In-depth Analysis**
    Zeek ships with analyzers for many protocols, enabling
    high-level semantic analysis at the application layer.

*   **Adaptable & Flexible**
    Zeek's domain specific scripting language enables site-specific
    monitoring policies and means that it is not restricted to any
    particular detection approach.

*   **Efficient**
    Zeek targets high-performance networks and is used operationally
    at a variety of large sites.

*   **Highly Stateful**
    Zeek keeps extensive application-layer state about the network
    it monitors and provides a high-level archive of a network's
    activity.

Getting Started
===============

The best place to find information about getting started with Zeek is
our web site https://www.zeek.org, specifically the documentation
section there [1]. One the web site you can also get downloads for
stable releases, tutorials on getting Zeek set up, and many other
useful resources.

You can find release notes in NEWS, and a complete record of all
changes in CHANGES.

To work with the most recent code from the development branch of Zeek,
clone the master git repository:

    > git clone --recursive https://github.com/zeek/zeek

With all dependencies [2] in place, build and install:

    > ./configure && make && sudo make install

Write your first Zeek script:

    # File "hello.zeek"

    event zeek_init()
        {
        print "Hello, World!";
        }

And run it:

    > zeek hello.zeek

For learning more about the Zeek scripting language,
https://try.zeek.org is a great resource.

Development
===========

Zeek is developed on GitHub by its community. We welcome
contributions. Working on an open source project like Zeek can be an
incredibly rewarding experience and, packet by packet, makes the
Internet a little safer. Today, as a result of countless
contributions, Zeek is used operationally around the world by major
companies and educational and scientific institutions alike for
securing their cyber infrastructure.

If you're interested in getting involved, we collect feature requests
and issues on GitHub. More information on Zeek's development can be
found here [2], and information about its community and mailing lists
(which are fairly active) can be found here [3].

License
-------

Zeek comes with a BSD license, allowing for free use with virtually no
restrictions. You can find it in COPYING.

Tooling
-------

We use the following tooling to help discover issues to fix, amongst a number of
others.

- Clang-Tidy [5]
- Coverity [6]
- PVS-Studio - static analyzer for C, C++, C#, and Java code [7]

[1] https://www.zeek.org/documentation/index.html
[2] https://docs.zeek.org/en/stable/install/install.html
[3] https://www.zeek.org/development/index.html
[4] https://www.zeek.org/community/index.html
[5] https://clang.llvm.org/extra/clang-tidy/
[6] https://scan.coverity.com/projects/bro
[7] https://pvs-studio.com/en/pvs-studio/?utm_source=github&utm_medium=organic&utm_campaign=open_source