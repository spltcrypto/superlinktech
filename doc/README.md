Bitcoin Core
=============

Setup
---------------------
Bitcoin Core is the original Bitcoin client and it builds the backbone of the network. It downloads and, by default, stores the entire history of Bitcoin transactions, which requires a few hundred gigabytes of disk space. Depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

To download Bitcoin Core, visit [superlinktechcore.org](https://superlinktechcore.org/en/download/).

Running
---------------------
The following are some helpful notes on how to run Bitcoin Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/superlinktech-qt` (GUI) or
- `bin/superlinktechd` (headless)

### Windows

Unpack the files into a directory, and then run superlinktech-qt.exe.

### macOS

Drag Bitcoin Core to your applications folder, and then run Bitcoin Core.

### Need Help?

* See the documentation at the [Bitcoin Wiki](https://en.superlinktech.it/wiki/Main_Page)
for help and more information.
* Ask for help on [#superlinktech](https://webchat.freenode.net/#superlinktech) on Freenode. If you don't have an IRC client, use [webchat here](https://webchat.freenode.net/#superlinktech).
* Ask for help on the [BitcoinTalk](https://superlinktechtalk.org/) forums, in the [Technical Support board](https://superlinktechtalk.org/index.php?board=4.0).

Building
---------------------
The following are developer notes on how to build Bitcoin Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)
- [Gitian Building Guide (External Link)](https://github.com/superlinktech-core/docs/blob/master/gitian-building.md)

Development
---------------------
The Bitcoin repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://doxygen.superlinktechcore.org/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)

### Resources
* Discuss on the [BitcoinTalk](https://superlinktechtalk.org/) forums, in the [Development & Technical Discussion board](https://superlinktechtalk.org/index.php?board=6.0).
* Discuss project-specific development on #superlinktech-core-dev on Freenode. If you don't have an IRC client, use [webchat here](https://webchat.freenode.net/#superlinktech-core-dev).
* Discuss general Bitcoin development on #superlinktech-dev on Freenode. If you don't have an IRC client, use [webchat here](https://webchat.freenode.net/#superlinktech-dev).

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [superlinktech.conf Configuration File](superlinktech-conf.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [ZMQ](zmq.md)
- [PSBT support](psbt.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
