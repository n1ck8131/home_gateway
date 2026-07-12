# Network namespace prerequisites

P0 proves only that the Linux lab has the required tools, root access and permission to create and remove a network namespace. Restricted containers can still deny these operations even when `CAP_NET_ADMIN` appears present.

P2 owns the routing topology, packet capture, DNS nftsets, fault injection and no-leak assertions.
