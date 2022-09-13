Binaries for Bitcoin version 0.3.21 are available at:
  https://sourceforge.net/projects/superlinktech/files/Bitcoin/superlinktech-0.3.21/

Changes and new features from the 0.3.20 release include:

* Universal Plug and Play support.  Enable automatic opening of a port for incoming connections by running superlinktech or superlinktechd with the - -upnp=1 command line switch or using the Options dialog box.

* Support for full-precision superlinktech amounts.  You can now send, and superlinktech will display, superlinktech amounts smaller than 0.01.  However, sending fewer than 0.01 superlinktechs still requires a 0.01 superlinktech fee (so you can send 1.0001 superlinktechs without a fee, but you will be asked to pay a fee if you try to send 0.0001).

* A new method of finding superlinktech nodes to connect with, via DNS A records. Use the -dnsseed option to enable.

For Developers, changes to superlinktech's remote-procedure-call API:

* New rpc command "sendmany" to send superlinktechs to more than one address in a single transaction.

* Several bug fixes, including a serious intermittent bug that would sometimes cause superlinktechd to stop accepting rpc requests. 

* -logtimestamps option, to add a timestamp to each line in debug.log.

* Immature blocks (newly generated, under 120 confirmations) are now shown in listtransactions.
