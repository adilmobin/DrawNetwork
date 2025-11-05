"""
Connection Discovery Engine
Analyzes network topology and discovers connections between devices
"""
from typing import List, Dict, Set, Tuple, Optional
from models.network_models import (
    NetworkDevice, NetworkTopology, Interface, Route, RoutingProtocol,
    ProtocolType, InterfaceType, VPN
)


class ConnectionDiscovery:
    """Discovers connections and relationships between network devices"""

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self.subnet_map = {}  # Maps subnets to list of (device, interface)
        self.ip_to_device = {}  # Maps IP addresses to (device, interface)
        self.discovered_connections = []
        self.routing_relationships = []

    def discover_all(self):
        """Main entry point - discover all connections and relationships"""
        self._build_maps()
        self._discover_layer3_connections()
        self._discover_routing_relationships()
        self._discover_vpn_tunnels()
        self._discover_nat_relationships()

    def _build_maps(self):
        """Build maps of IP addresses and subnets"""
        for device in self.topology.devices:
            for interface in device.interfaces:
                if interface.ip_address and interface.subnet_mask and interface.enabled:
                    # Calculate subnet
                    subnet = self._calculate_subnet(interface.ip_address, interface.subnet_mask)

                    # Add to subnet map
                    if subnet not in self.subnet_map:
                        self.subnet_map[subnet] = []
                    self.subnet_map[subnet].append((device, interface))

                    # Add to IP map
                    self.ip_to_device[interface.ip_address] = (device, interface)

    def _discover_layer3_connections(self):
        """Discover Layer 3 connections based on shared subnets"""
        for subnet, members in self.subnet_map.items():
            if len(members) >= 2:
                # Create connections between all devices on same subnet
                for i in range(len(members)):
                    for j in range(i + 1, len(members)):
                        device1, intf1 = members[i]
                        device2, intf2 = members[j]

                        # Add connection to topology
                        connection = {
                            'device1': device1.hostname,
                            'interface1': intf1.name,
                            'ip1': intf1.ip_address,
                            'device2': device2.hostname,
                            'interface2': intf2.name,
                            'ip2': intf2.ip_address,
                            'subnet': subnet,
                            'type': 'layer3'
                        }

                        # Check if connection already exists
                        if not self._connection_exists(connection):
                            self.topology.add_connection(
                                device1.hostname,
                                intf1.name,
                                device2.hostname,
                                intf2.name
                            )
                            self.discovered_connections.append(connection)

    def _discover_routing_relationships(self):
        """Discover routing protocol relationships (OSPF neighbors, BGP peers, etc.)"""
        # OSPF adjacencies - devices in same subnet running OSPF
        self._discover_ospf_adjacencies()

        # BGP peerings - explicit neighbor relationships
        self._discover_bgp_peerings()

        # Static route next-hops
        self._discover_static_route_relationships()

    def _discover_ospf_adjacencies(self):
        """Discover OSPF adjacencies"""
        for subnet, members in self.subnet_map.items():
            ospf_devices = []

            for device, interface in members:
                # Check if device runs OSPF
                has_ospf = any(p.protocol == ProtocolType.OSPF for p in device.routing_protocols)
                if has_ospf:
                    ospf_devices.append((device, interface))

            # Create OSPF adjacency relationships
            if len(ospf_devices) >= 2:
                for i in range(len(ospf_devices)):
                    for j in range(i + 1, len(ospf_devices)):
                        device1, intf1 = ospf_devices[i]
                        device2, intf2 = ospf_devices[j]

                        relationship = {
                            'type': 'ospf_adjacency',
                            'device1': device1.hostname,
                            'device2': device2.hostname,
                            'interface1': intf1.name,
                            'interface2': intf2.name,
                            'subnet': subnet
                        }

                        self.routing_relationships.append(relationship)

    def _discover_bgp_peerings(self):
        """Discover BGP peering relationships"""
        for device in self.topology.devices:
            for protocol in device.routing_protocols:
                if protocol.protocol == ProtocolType.BGP:
                    for neighbor_ip in protocol.neighbors:
                        # Find the neighbor device
                        if neighbor_ip in self.ip_to_device:
                            neighbor_device, neighbor_intf = self.ip_to_device[neighbor_ip]

                            relationship = {
                                'type': 'bgp_peering',
                                'device1': device.hostname,
                                'device2': neighbor_device.hostname,
                                'neighbor_ip': neighbor_ip,
                                'local_as': protocol.autonomous_system
                            }

                            self.routing_relationships.append(relationship)

    def _discover_static_route_relationships(self):
        """Discover static route next-hop relationships"""
        for device in self.topology.devices:
            for route in device.routes:
                if route.protocol == ProtocolType.STATIC and route.next_hop:
                    # Find device with this next-hop IP
                    if route.next_hop in self.ip_to_device:
                        next_hop_device, next_hop_intf = self.ip_to_device[route.next_hop]

                        relationship = {
                            'type': 'static_route',
                            'source_device': device.hostname,
                            'next_hop_device': next_hop_device.hostname,
                            'next_hop_ip': route.next_hop,
                            'destination': route.destination,
                            'mask': route.mask
                        }

                        self.routing_relationships.append(relationship)

    def _discover_vpn_tunnels(self):
        """Discover VPN tunnel relationships"""
        for device in self.topology.devices:
            for vpn in device.vpn_configs:
                if vpn.peer:
                    # Try to find the peer device
                    peer_device = self._find_device_by_ip(vpn.peer)

                    if peer_device:
                        relationship = {
                            'type': 'vpn_tunnel',
                            'device1': device.hostname,
                            'device2': peer_device.hostname,
                            'peer_ip': vpn.peer,
                            'tunnel_name': vpn.name,
                            'vpn_type': vpn.type
                        }

                        self.routing_relationships.append(relationship)

    def _discover_nat_relationships(self):
        """Discover NAT relationships (which devices have NAT rules)"""
        for device in self.topology.devices:
            if device.nat_rules:
                for nat in device.nat_rules:
                    # Track NAT relationships for documentation
                    if nat.translated_source or nat.translated_destination:
                        relationship = {
                            'type': 'nat',
                            'device': device.hostname,
                            'nat_type': nat.type,
                            'original_source': nat.original_source,
                            'translated_source': nat.translated_source
                        }

                        self.routing_relationships.append(relationship)

    def _connection_exists(self, connection: Dict) -> bool:
        """Check if a connection already exists in discovered connections"""
        for conn in self.discovered_connections:
            if (conn['device1'] == connection['device1'] and conn['device2'] == connection['device2']) or \
               (conn['device1'] == connection['device2'] and conn['device2'] == connection['device1']):
                return True
        return False

    def _find_device_by_ip(self, ip: str) -> Optional[NetworkDevice]:
        """Find device by IP address"""
        if ip in self.ip_to_device:
            device, _ = self.ip_to_device[ip]
            return device
        return None

    def _calculate_subnet(self, ip: str, netmask: str) -> str:
        """Calculate subnet from IP and netmask"""
        try:
            ip_parts = [int(p) for p in ip.split('.')]
            mask_parts = [int(p) for p in netmask.split('.')]
            subnet_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            cidr = self._netmask_to_cidr(netmask)
            return '.'.join(str(p) for p in subnet_parts) + f'/{cidr}'
        except:
            return ip

    def _netmask_to_cidr(self, netmask: str) -> int:
        """Convert netmask to CIDR"""
        try:
            parts = [int(p) for p in netmask.split('.')]
            binary = ''.join([bin(p)[2:].zfill(8) for p in parts])
            return binary.count('1')
        except:
            return 24

    def get_connection_summary(self) -> str:
        """Get a summary of discovered connections"""
        summary = f"Connection Discovery Summary:\n"
        summary += f"  Total Devices: {len(self.topology.devices)}\n"
        summary += f"  Discovered Layer 3 Connections: {len(self.discovered_connections)}\n"
        summary += f"  Routing Relationships: {len(self.routing_relationships)}\n"

        # Count by type
        ospf_count = len([r for r in self.routing_relationships if r['type'] == 'ospf_adjacency'])
        bgp_count = len([r for r in self.routing_relationships if r['type'] == 'bgp_peering'])
        vpn_count = len([r for r in self.routing_relationships if r['type'] == 'vpn_tunnel'])

        if ospf_count > 0:
            summary += f"    - OSPF Adjacencies: {ospf_count}\n"
        if bgp_count > 0:
            summary += f"    - BGP Peerings: {bgp_count}\n"
        if vpn_count > 0:
            summary += f"    - VPN Tunnels: {vpn_count}\n"

        return summary

    def print_discovered_connections(self):
        """Print discovered connections for debugging"""
        print("\n" + "="*70)
        print("DISCOVERED CONNECTIONS")
        print("="*70)

        if self.discovered_connections:
            for conn in self.discovered_connections:
                print(f"\n{conn['device1']} ({conn['interface1']}: {conn['ip1']})")
                print(f"  ⟷  ")
                print(f"{conn['device2']} ({conn['interface2']}: {conn['ip2']})")
                print(f"  Subnet: {conn['subnet']}")
        else:
            print("No connections discovered")

        print("\n" + "="*70)
        print("ROUTING RELATIONSHIPS")
        print("="*70)

        if self.routing_relationships:
            for rel in self.routing_relationships:
                if rel['type'] == 'ospf_adjacency':
                    print(f"\nOSPF Adjacency:")
                    print(f"  {rel['device1']} ⟷ {rel['device2']}")
                    print(f"  Subnet: {rel['subnet']}")

                elif rel['type'] == 'bgp_peering':
                    print(f"\nBGP Peering:")
                    print(f"  {rel['device1']} → {rel['device2']}")
                    print(f"  Peer IP: {rel['neighbor_ip']}")

                elif rel['type'] == 'static_route':
                    print(f"\nStatic Route:")
                    print(f"  {rel['source_device']} → {rel['next_hop_device']}")
                    print(f"  Destination: {rel['destination']}/{rel['mask']}")
                    print(f"  Next Hop: {rel['next_hop_ip']}")

                elif rel['type'] == 'vpn_tunnel':
                    print(f"\nVPN Tunnel:")
                    print(f"  {rel['device1']} ⟷ {rel['device2']}")
                    print(f"  Peer IP: {rel['peer_ip']}")
                    print(f"  Type: {rel['vpn_type']}")
        else:
            print("No routing relationships discovered")

        print("\n" + "="*70)
