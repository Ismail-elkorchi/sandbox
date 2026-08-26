# Protocol fuzz target

Run `cargo fuzz run protocol`. The target repeatedly decodes frames from arbitrary byte streams and parses control JSON while the decoder's declared-payload limits remain authoritative.
