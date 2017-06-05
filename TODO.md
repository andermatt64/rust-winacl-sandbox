# TODOs
* (DONE) Split AppContainerProfile and SimpleDacl into separate files
* (DONE) Create unit tests for:
  * (DONE) AppContainerProfile and SimpleDacl
* (DONE) Find an async IO framework that can setup a server socket over TCP
  * (DONE)[Wrote our own because mio didn't work] Figure out how to convert their sockets into raw Windows SOCKET
* (DONE) Use clap-rs for argument parsing
* (DONE) Think about using log and env_logger for debug logging: https://techsaju.wordpress.com/2015/09/12/logging-in-rust-using-log/
