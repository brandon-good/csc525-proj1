Use `make` to compile, and feel free to replace the compilation flags (I have "RELEASE_FLAGS" just to get rid of the debug logging, asserts, etc.).

Okay I finally figured out the bug I was struggling with -- good old pointer math. Anyways, all of the packet interactions are now functioning in this version. All that needs to occur is computing the shortest path and updating the routing table.

So the things that work are:
- Hello packets from both threads
- LSU packets from both threads (timeouts, forwarding vs not, etc.)
- Maintaining the global topology via an adjacency

I do not currently
- Compute the shortest path
- Update the routing table at all

This will run with the static routing tables, but still has the minor bug from part 1 where there is an occasional 1 second delay.


