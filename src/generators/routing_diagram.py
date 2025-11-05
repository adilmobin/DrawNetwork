"""
Routing Diagram Generator
Shows routing protocols, routing domains, and route propagation
"""
from typing import Dict, List, Set, Tuple
from generators.drawio_generator import DrawIOGenerator
from models.network_models import NetworkDevice, NetworkTopology, ProtocolType


class RoutingDiagram(DrawIOGenerator):
    """Generator for routing diagrams"""

    def generate(self, topology: NetworkTopology, filename: str):
        """Generate routing diagram"""
        mxfile, root = self.create_diagram("Routing Diagram")

        # Group devices by routing protocol/domain
        routing_domains = self._identify_routing_domains(topology)

        # Draw routing domains
        domain_positions = self._draw_routing_domains(root, routing_domains, topology)

        # Draw devices
        device_positions = self._draw_routing_devices(root, topology, domain_positions)

        # Draw routing relationships
        self._draw_routing_relationships(root, topology, device_positions)

        # Add route summary
        self._add_route_summary(root, topology)

        # Save diagram
        self.save_diagram(mxfile, filename)

    def _identify_routing_domains(self, topology: NetworkTopology) -> Dict[str, Dict]:
        """Identify routing domains (OSPF areas, BGP AS, etc.)"""
        domains = {}

        for device in topology.devices:
            for protocol in device.routing_protocols:
                domain_key = None

                if protocol.protocol == ProtocolType.OSPF:
                    domain_key = f"OSPF_{protocol.process_id or '1'}"
                    if domain_key not in domains:
                        domains[domain_key] = {
                            'type': 'OSPF',
                            'process_id': protocol.process_id,
                            'devices': [],
                            'areas': set()
                        }
                    domains[domain_key]['devices'].append(device.hostname)
                    if protocol.areas:
                        domains[domain_key]['areas'].update(protocol.areas)

                elif protocol.protocol == ProtocolType.BGP:
                    domain_key = f"BGP_AS{protocol.autonomous_system or 'unknown'}"
                    if domain_key not in domains:
                        domains[domain_key] = {
                            'type': 'BGP',
                            'as_number': protocol.autonomous_system,
                            'devices': [],
                            'neighbors': set()
                        }
                    domains[domain_key]['devices'].append(device.hostname)
                    if protocol.neighbors:
                        domains[domain_key]['neighbors'].update(protocol.neighbors)

                elif protocol.protocol == ProtocolType.EIGRP:
                    domain_key = f"EIGRP_{protocol.autonomous_system or protocol.process_id or '1'}"
                    if domain_key not in domains:
                        domains[domain_key] = {
                            'type': 'EIGRP',
                            'as_number': protocol.autonomous_system,
                            'devices': []
                        }
                    domains[domain_key]['devices'].append(device.hostname)

        return domains

    def _draw_routing_domains(self, root, domains: Dict, topology: NetworkTopology) -> Dict:
        """Draw routing domain containers"""
        domain_positions = {}
        y = 100
        x_spacing = 600

        for i, (domain_key, domain_data) in enumerate(domains.items()):
            x = 100 + (i % 2) * x_spacing

            # Create domain container
            domain_name = f"{domain_data['type']} Domain"
            if domain_data['type'] == 'OSPF':
                domain_name += f" (Process {domain_data.get('process_id', '1')})"
                if domain_data.get('areas'):
                    domain_name += f"\nAreas: {', '.join(str(a) for a in sorted(domain_data['areas']))}"
            elif domain_data['type'] == 'BGP':
                domain_name += f" (AS {domain_data.get('as_number', 'unknown')})"
            elif domain_data['type'] == 'EIGRP':
                domain_name += f" (AS {domain_data.get('as_number', '1')})"

            # Calculate container size based on number of devices
            num_devices = len(domain_data['devices'])
            height = max(300, 100 + num_devices * 60)

            domain_id = self.add_network_segment(root, domain_name, x, y, width=500, height=height)
            domain_positions[domain_key] = (domain_id, x, y, height)

            if i % 2 == 1:
                y += height + 50

        return domain_positions

    def _draw_routing_devices(self, root, topology: NetworkTopology,
                              domain_positions: Dict) -> Dict:
        """Draw devices within their routing domains"""
        device_positions = {}

        # Track which devices are placed in domains
        placed_devices = set()

        # Place devices in their routing domains
        for domain_key, (domain_id, x, y, height) in domain_positions.items():
            domain_data = self._get_domain_data(topology, domain_key)
            devices = domain_data['devices']

            y_device = y + 60
            for device_name in devices:
                device = topology.get_device(device_name)
                if device:
                    device_id = self.add_router(root, device_name, x + 20, y_device)
                    device_positions[device_name] = (device_id, x + 20, y_device)
                    placed_devices.add(device_name)

                    # Add routing info
                    routing_info = self._get_routing_info(device, domain_key)
                    if routing_info:
                        self.add_text_label(root, routing_info, x + 130, y_device + 10, width=300, height=80)

                    y_device += 100

        # Place devices without routing protocols
        y_static = 100
        for device in topology.devices:
            if device.hostname not in placed_devices:
                # Check if device has static routes
                if device.routes:
                    device_id = self.add_router(root, device.hostname, 800, y_static)
                    device_positions[device.hostname] = (device_id, 800, y_static)

                    # Add static route info
                    route_info = f"Static Routes: {len(device.routes)}"
                    self.add_text_label(root, route_info, 910, y_static + 10, width=200, height=30)

                    y_static += 120

        return device_positions

    def _draw_routing_relationships(self, root, topology: NetworkTopology,
                                    device_positions: Dict):
        """Draw routing protocol relationships"""
        # Draw OSPF adjacencies
        self._draw_ospf_adjacencies(root, topology, device_positions)

        # Draw BGP peerings
        self._draw_bgp_peerings(root, topology, device_positions)

        # Draw static route next hops
        self._draw_static_routes(root, topology, device_positions)

    def _draw_ospf_adjacencies(self, root, topology: NetworkTopology, device_positions: Dict):
        """Draw OSPF adjacencies between routers"""
        # Build subnet map to find OSPF neighbors
        subnet_map = {}

        for device in topology.devices:
            if not device.routing_protocols:
                continue

            has_ospf = any(p.protocol == ProtocolType.OSPF for p in device.routing_protocols)
            if not has_ospf:
                continue

            for interface in device.interfaces:
                if interface.ip_address and interface.subnet_mask and interface.enabled:
                    subnet = self._calculate_subnet(interface.ip_address, interface.subnet_mask)
                    if subnet not in subnet_map:
                        subnet_map[subnet] = []
                    subnet_map[subnet].append(device.hostname)

        # Create OSPF adjacency connections
        for subnet, devices in subnet_map.items():
            if len(devices) >= 2:
                for i in range(len(devices) - 1):
                    device1 = devices[i]
                    device2 = devices[i + 1]

                    if device1 in device_positions and device2 in device_positions:
                        source_id = device_positions[device1][0]
                        target_id = device_positions[device2][0]

                        label = f"OSPF\\nSubnet: {subnet}"
                        style = (
                            'endArrow=classic;startArrow=classic;html=1;rounded=0;'
                            'strokeColor=#0066CC;strokeWidth=2;'
                        )

                        self.add_connection(root, source_id, target_id, label, style)

    def _draw_bgp_peerings(self, root, topology: NetworkTopology, device_positions: Dict):
        """Draw BGP peering relationships"""
        for device in topology.devices:
            for protocol in device.routing_protocols:
                if protocol.protocol == ProtocolType.BGP:
                    for neighbor in protocol.neighbors:
                        # Try to find the neighbor device
                        neighbor_device = self._find_device_by_ip(topology, neighbor)

                        if neighbor_device and neighbor_device.hostname in device_positions:
                            if device.hostname in device_positions:
                                source_id = device_positions[device.hostname][0]
                                target_id = device_positions[neighbor_device.hostname][0]

                                label = f"BGP Peering\\n{neighbor}"
                                style = (
                                    'endArrow=classic;startArrow=classic;html=1;rounded=0;'
                                    'strokeColor=#CC6600;strokeWidth=2;dashed=1;'
                                )

                                self.add_connection(root, source_id, target_id, label, style)

    def _draw_static_routes(self, root, topology: NetworkTopology, device_positions: Dict):
        """Draw static route next hops"""
        for device in topology.devices:
            for route in device.routes:
                if route.protocol == ProtocolType.STATIC and route.next_hop:
                    # Try to find device with this next hop
                    next_hop_device = self._find_device_by_ip(topology, route.next_hop)

                    if next_hop_device and next_hop_device.hostname in device_positions:
                        if device.hostname in device_positions:
                            source_id = device_positions[device.hostname][0]
                            target_id = device_positions[next_hop_device.hostname][0]

                            label = f"Static Route\\n{route.destination}/{route.mask}"
                            style = (
                                'endArrow=classic;html=1;rounded=0;'
                                'strokeColor=#009900;strokeWidth=2;dashed=1;dashPattern=8 8;'
                            )

                            self.add_connection(root, source_id, target_id, label, style)

    def _add_route_summary(self, root, topology: NetworkTopology):
        """Add route summary legend"""
        legend_x = 50
        legend_y = 600

        # Count routes by protocol
        route_counts = {
            'OSPF': 0,
            'BGP': 0,
            'EIGRP': 0,
            'Static': 0
        }

        for device in topology.devices:
            for protocol in device.routing_protocols:
                if protocol.protocol == ProtocolType.OSPF:
                    route_counts['OSPF'] += len(protocol.networks)
                elif protocol.protocol == ProtocolType.BGP:
                    route_counts['BGP'] += len(protocol.networks)
                elif protocol.protocol == ProtocolType.EIGRP:
                    route_counts['EIGRP'] += len(protocol.networks)

            route_counts['Static'] += len([r for r in device.routes if r.protocol == ProtocolType.STATIC])

        # Create legend
        legend_text = "Route Summary:\n"
        for protocol, count in route_counts.items():
            if count > 0:
                legend_text += f"• {protocol}: {count} route(s)\n"

        self.add_text_label(root, legend_text, legend_x, legend_y, width=200, height=100)

    def _get_domain_data(self, topology: NetworkTopology, domain_key: str) -> Dict:
        """Get domain data by reconstructing it"""
        domains = self._identify_routing_domains(topology)
        return domains.get(domain_key, {'devices': []})

    def _get_routing_info(self, device: NetworkDevice, domain_key: str) -> str:
        """Get routing information for device in domain"""
        info = []

        for protocol in device.routing_protocols:
            if domain_key.startswith('OSPF') and protocol.protocol == ProtocolType.OSPF:
                if protocol.router_id:
                    info.append(f"Router ID: {protocol.router_id}")
                if protocol.networks:
                    info.append(f"Networks: {len(protocol.networks)}")

            elif domain_key.startswith('BGP') and protocol.protocol == ProtocolType.BGP:
                if protocol.router_id:
                    info.append(f"Router ID: {protocol.router_id}")
                if protocol.neighbors:
                    info.append(f"Peers: {len(protocol.neighbors)}")

            elif domain_key.startswith('EIGRP') and protocol.protocol == ProtocolType.EIGRP:
                if protocol.networks:
                    info.append(f"Networks: {len(protocol.networks)}")

        return "\n".join(info)

    def _find_device_by_ip(self, topology: NetworkTopology, ip: str) -> NetworkDevice:
        """Find device that has the given IP address"""
        for device in topology.devices:
            for interface in device.interfaces:
                if interface.ip_address == ip:
                    return device
        return None

    def _calculate_subnet(self, ip: str, netmask: str) -> str:
        """Calculate subnet from IP and netmask"""
        try:
            ip_parts = [int(p) for p in ip.split('.')]
            mask_parts = [int(p) for p in netmask.split('.')]
            subnet_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            return '.'.join(str(p) for p in subnet_parts)
        except:
            return ip
