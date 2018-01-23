Ashutosh Mahajan N15565485 abm523

The project is run on Virtual Box atop a Floodlight OpenFlow controller.
The Virtual Machine is a 64-bit Ubuntu OS preloaded with Mininet and Floodlight and Eclipse for debugging.
Mininet is used for creating virtual network topologies

Implementation of Layer-3 Shortest Path Switching Routing Application.
--> A Routing Application that uses Bellman Ford Algorithm for computing the shortest path between nodes.
--> Finds the next switch on path and then installs rules in the flow table at every switch on path.
--> The network is an undirected graph with switches forming the network and hosts connected to the switches.
--> Rules are installed using the installRulesHost method.
--> ARP requests are not broad-casted but are sent to the controller.

Implementation of Distributed Load Balance Routing Application.
--> Instances are initialized from the loadbalancer.prop as can be seen in the output. It has its own Virtual IP and MAC
--> For each new connection the loadbalancer selects one of the hosts (in round robin fashion).
--> The application rewrites the destination addresses with the host's addresses.
--> Install rule in a switch in three cases
	--> TCP connection --> Construct and send SYN packet
	--> ARP message --> Construct and send ARP reply
	--> Other connection message --> Do nothing
--> IDLE_TIMEOUT is 20 seconds

Switch Commands are used wherever required.
Topology information is gathered using getHosts(), getLinks(), getSwitches() methods.

