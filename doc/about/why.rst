.. _why-zeek:

Why Zeek?
=========

Zeek offers many advantages for security and network teams who want to better
understand how their infrastructure is being used.

Security teams generally depend upon four sorts of data sources when trying to
detect and respond to suspicious and malicious activity. These include *third
party* sources such as law enforcement, peers, and commercial or nonprofit
threat intelligence organizations; *network data*; *infrastructure and
application data*, including logs from cloud environments; and *endpoint data*.
Zeek is primarily a platform for collecting and analyzing the second form of
data -- network data. All four are important elements of any security team’s
program, however.

When looking at data derived from the network, there are four types of data
available to analysts. As defined by the `network security monitoring paradigm
<https://corelight.com/blog/do-you-know-your-nsm-data-types>`_, these
four data types are *full content*, *transaction data*, *extracted content*,
and *alert data*. Using these data types, one can record traffic, summarize
traffic, extract traffic (or perhaps more accurately, extract content
in the form of files), and judge traffic, respectively.

It’s critical to collect and analyze the four types of network security
monitoring data. The question becomes one of determining the best way to
accomplish this goal. Thankfully, Zeek as a NSM platform enables collection of
at least two, and in some ways three, of these data forms, namely transaction
data, extracted content, and alert data.

Zeek is best known for its transaction data. By default, when run and told to
watch a network interface, Zeek will generate a collection of compact,
high-fidelity, richly-annotated set of transaction logs. These logs describe
the protocols and activity seen on the wire, in a judgement-free,
policy-neutral manner. This documentation will spend a considerable amount of
time describing the most common Zeek log files such that readers will become
comfortable with the format and learn to apply them to their environment.

Zeek can also easily carve files from network traffic, thanks to its file
extraction capabilities. Analysts can then send those files to execution
sandboxes or other file examination tools for additional investigation. Zeek
has some capability to perform classical byte-centric intrusion detection, but
that job is best suited for packages like the open source Snort or Suricata
engines. Zeek has other capabilities however that are capable of providing
judgements in the form of alerts, through its notice mechanism.

Zeek is not optimized for writing traffic to disk in the spirit of a full
content data collection, and that task is best handled by software written to
fulfill that requirement.

Beyond the forms of network data that Zeek can natively collect and generate,
Zeek has advantages that appeared in the :ref:`what-is-zeek` section. These
include its built-in functionality for a range of analysis and detection
tasks, and its status as a fully customizable and extensible platform for
traffic analysis.  Zeek is also attractive because of its ability to run on
commodity hardware, giving users of all types the ability to at least try Zeek
in a low-cost manner.
