"""
Detailed Routing Diagram Generator
Shows individual routing protocol peerings with VRF/VR awareness
"""
from typing import Dict, List, Set, Tuple
from generators.drawio_generator import DrawIOGenerator
from models.network_models import NetworkDevice, NetworkTopology, ProtocolType, VirtualRouter


class DetailedRoutingDiagram(DrawIOGenerator):
    """Generator for detailed routing diagrams showing every neighbor relationship"""

    def generate(self, topology: NetworkTopology, filename: str):
        """Generate detailed routing diagram with individual peer connections"""
        mxfile, root = self.create_diagram("Detailed Routing Diagram")

        # Layout: Group devices by VR/VRF, show each protocol instance
        y_offset = 100
        x_offset = 100
        spacing = 300

        # Collect all VRs across all devices
        vr_map = self._collect_virtual_routers(topology)

        # Draw VR containers with devices
        vr_boxes = {}
        for vr_key, vr_data in vr_map.items():
            box_id, box_y = self._draw_vr_container(root, vr_key, vr_data, x_offset, y_offset)
            vr_boxes[vr_key] = (box_id, x_offset, box_y)
            y_offset += 350

        # Draw individual OSPF adjacencies
        self._draw_ospf_adjacencies(root, topology, vr_map)

        # Draw individual BGP peerings
        self._draw_bgp_peerings(root, topology, vr_map)

        # Draw legend
        self._draw_legend(root)

        # Save diagram
        self.save_diagram(mxfile, filename)

    def _collect_virtual_routers(self, topology: NetworkTopology) -> Dict:
        """Collect all VRs from all devices"""
        vr_map = {}

        for device in topology.devices:
            # Handle devices with VRs
            if device.virtual_routers:
                for vr in device.virtual_routers:
                    vr_key = f"{device.hostname}:{vr.name}"
                    if vr.vsys:
                        vr_key += f" (VSYS:{vr.vsys})"

                    vr_map[vr_key] = {
                        'device': device,
                        'vr': vr,
                        'routing_protocols': vr.routing_protocols,
                        'routes': vr.routes
                    }

            # Handle devices with global routing (no VR)
            elif device.routing_protocols or device.routes:
                vr_key = f"{device.hostname}:global"
                vr_map[vr_key] = {
                    'device': device,
                    'vr': None,
                    'routing_protocols': device.routing_protocols,
                    'routes': device.routes
                }

        return vr_map

    def _draw_vr_container(self, root, vr_key: str, vr_data: Dict, x: int, y: int) -> Tuple:
        """Draw a VR container with device and protocol info"""
        device = vr_data['device']
        vr = vr_data['vr']

        # Container
        container_id = self.add_network_segment(root, vr_key, x, y, width=800, height=300)

        # Device icon
        device_id = self.add_router(root, device.hostname, x + 20, y + 40)
        self.cell_map[vr_key] = device_id

        # VR details
        details_y = y + 60
        for protocol in vr_data['routing_protocols']:
            protocol_text = f"{protocol.protocol.value.upper()}"
            if protocol.router_id:
                protocol_text += f" - Router ID: {protocol.router_id}"
            if protocol.protocol == ProtocolType.BGP and protocol.autonomous_system:
                protocol_text += f" (AS {protocol.autonomous_system})"
            if protocol.protocol == ProtocolType.OSPF and protocol.areas:
                protocol_text += f" Areas: {', '.join(protocol.areas)}"

            # List each neighbor
            if protocol.neighbors:
                protocol_text += f"\nConfigured Peers: {len(protocol.neighbors)}"
                for i, neighbor in enumerate(protocol.neighbors[:5]):  # Show first 5
                    protocol_text += f"\n  • {neighbor}"
                if len(protocol.neighbors) > 5:
                    protocol_text += f"\n  • ...and {len(protocol.neighbors) - 5} more"

            self.add_text_label(root, protocol_text, x + 150, details_y, width=600, height=120)
            details_y += 130

        return container_id, y

    def _draw_ospf_adjacencies(self, root, topology: NetworkTopology, vr_map: Dict):
        """Draw individual OSPF neighbor relationships"""
        # Build map of interfaces by IP
        ip_to_vr = {}
        for vr_key, vr_data in vr_map.items():
            device = vr_data['device']
            vr = vr_data['vr']

            # Find interfaces in this VR
            for intf in device.interfaces:
                if intf.ip_address and intf.enabled:
                    # Check if interface belongs to this VR
                    if (vr and intf.vrf == vr.name) or (not vr and not intf.vrf):
                        if intf.ip_address not in ip_to_vr:
                            ip_to_vr[intf.ip_address] = []
                        ip_to_vr[intf.ip_address].append({
                            'vr_key': vr_key,
                            'device': device,
                            'interface': intf
                        })

        # Find OSPF-enabled VRs on same subnet
        subnet_ospf_map = {}
        for vr_key, vr_data in vr_map.items():
            device = vr_data['device']

            # Check if this VR has OSPF
            has_ospf = any(p.protocol == ProtocolType.OSPF for p in vr_data['routing_protocols'])
            if not has_ospf:
                continue

            # Find interfaces in this VR
            for intf in device.interfaces:
                if intf.ip_address and intf.subnet_mask and intf.enabled:
                    # Check if interface belongs to this VR
                    vr = vr_data['vr']
                    if (vr and intf.vrf == vr.name) or (not vr and not intf.vrf):
                        subnet = self._calculate_subnet(intf.ip_address, intf.subnet_mask)
                        if subnet not in subnet_ospf_map:
                            subnet_ospf_map[subnet] = []
                        subnet_ospf_map[subnet].append({
                            'vr_key': vr_key,
                            'device': device,
                            'interface': intf
                        })

        # Draw OSPF adjacency for each pair on same subnet
        drawn_pairs = set()
        for subnet, members in subnet_ospf_map.items():
            if len(members) >= 2:
                for i in range(len(members)):
                    for j in range(i + 1, len(members)):
                        vr_key1 = members[i]['vr_key']
                        vr_key2 = members[j]['vr_key']

                        pair = tuple(sorted([vr_key1, vr_key2]))
                        if pair in drawn_pairs:
                            continue
                        drawn_pairs.add(pair)

                        if vr_key1 in self.cell_map and vr_key2 in self.cell_map:
                            source_id = self.cell_map[vr_key1]
                            target_id = self.cell_map[vr_key2]

                            label = f"OSPF Adjacency\\nSubnet: {subnet}"
                            style = (
                                'endArrow=classic;startArrow=classic;html=1;rounded=0;'
                                'strokeColor=#0066CC;strokeWidth=3;'
                            )

                            self.add_connection(root, source_id, target_id, label, style)

    def _draw_bgp_peerings(self, root, topology: NetworkTopology, vr_map: Dict):
        """Draw individual BGP peer relationships"""
        # Build IP to VR mapping
        ip_to_vr = {}
        for vr_key, vr_data in vr_map.items():
            device = vr_data['device']
            vr = vr_data['vr']

            for intf in device.interfaces:
                if intf.ip_address and intf.enabled:
                    if (vr and intf.vrf == vr.name) or (not vr and not intf.vrf):
                        ip_to_vr[intf.ip_address] = vr_key

        # Draw each BGP peer as individual connection
        drawn_pairs = set()
        for vr_key, vr_data in vr_map.items():
            for protocol in vr_data['routing_protocols']:
                if protocol.protocol == ProtocolType.BGP:
                    for neighbor_ip in protocol.neighbors:
                        # Find the neighbor's VR
                        if neighbor_ip in ip_to_vr:
                            neighbor_vr_key = ip_to_vr[neighbor_ip]

                            pair = tuple(sorted([vr_key, neighbor_vr_key]))
                            if pair in drawn_pairs:
                                continue
                            drawn_pairs.add(pair)

                            if vr_key in self.cell_map and neighbor_vr_key in self.cell_map:
                                source_id = self.cell_map[vr_key]
                                target_id = self.cell_map[neighbor_vr_key]

                                label = f"BGP Peering\\nPeer: {neighbor_ip}"
                                if protocol.autonomous_system:
                                    label += f"\\nLocal AS: {protocol.autonomous_system}"

                                style = (
                                    'endArrow=classic;startArrow=classic;html=1;rounded=0;'
                                    'strokeColor=#CC6600;strokeWidth=3;dashed=1;'
                                )

                                self.add_connection(root, source_id, target_id, label, style)

    def _draw_legend(self, root):
        """Draw legend explaining the diagram"""
        legend_x = 900
        legend_y = 50

        legend_text = (
            "Legend:\\n"
            "━━━ OSPF Adjacency (solid blue)\\n"
            "- - - BGP Peering (dashed orange)\\n\\n"
            "Each box represents a VR/VRF\\n"
            "Lines show individual neighbor relationships"
        )

        self.add_text_label(root, legend_text, legend_x, legend_y, width=250, height=150)

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
