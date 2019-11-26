# host-based-firewall
Firewall class that sets up firewall rules upon initialization and looks up for incoming traffic.
If a packet matches a firewall rule, the packet is accepted else it is rejected.

Data structure used to hold firewall rules:
A binary search tree with port number as a key is used to hold firewall rules.
With more time at hand, an AVL tree would have been a preferred choice for optimized results.

The file input.txt contains the firewall rules this code has been tested with.

The test cases have been written at the end of the script. (inside "if name main block")
 
To run the tests simply run the code on python interpreter. Make sure input.txt lies on the same level to that of firewall.py

> python3 firewall.py

If given an opportunity, the preferred choice would be to work with the data team second choice being the platform team.