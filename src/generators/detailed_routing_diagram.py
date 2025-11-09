"""
Detailed Routing Diagram Generator
Shows individual routing protocol peers as separate device boxes with connections
"""
from typing import Dict, List, Set, Tuple
from generators.drawio_generator import DrawIOGenerator
from models.network_models import NetworkDevice, NetworkTopology, ProtocolType, VirtualRouter


class DetailedRoutingDiagram(DrawIOGenerator):
    """Generator for detailed routing diagrams showing every neighbor as a separate box"""

    def generate(self, topology: NetworkTopology, filename: str):
        """Generate detailed routing diagram with individual peer boxes"""
        mxfile, root = self.create_diagram("Detailed Routing Diagram")

        # Layout configuration
        device_spacing_y = 400
        peer_spacing_x = 300
        start_x = 100
        start_y = 100

        current_y = start_y

        # Collect all VRs/routing instances across all devices
        vr_map = self._collect_virtual_routers(topology)

        # For each VR/device, draw it and all its peers
        for vr_key, vr_data in vr_map.items():
            device = vr_data['device']
            vr = vr_data['vr']

            # Draw the main device/VR box
            device_x = start_x
            device_y = current_y

            device_label = self._build_device_label(device, vr, vr_data)
            device_id = self.add_router(root, device_label, device_x, device_y, label_text=device_label)
            self.cell_map[vr_key] = device_id

            # Draw BGP peers
            peer_x = device_x + peer_spacing_x
            peer_y = device_y

            for protocol in vr_data['routing_protocols']:
                if protocol.protocol == ProtocolType.BGP:
                    # Use bgp_peers if available (has AS info), otherwise fall back to neighbors
                    peers_to_draw = protocol.bgp_peers if protocol.bgp_peers else [{'ip': n} for n in protocol.neighbors]

                    for peer_info in peers_to_draw:
                        peer_ip = peer_info.get('ip', peer_info) if isinstance(peer_info, dict) else peer_info

                        # Draw each BGP peer as separate box
                        peer_label = self._build_bgp_peer_label(peer_info, protocol)
                        peer_id = self.add_router(root, f"BGP-{peer_ip}", peer_x, peer_y, label_text=peer_label)

                        # Draw connection line
                        label = f"BGP Peering"
                        if protocol.autonomous_system:
                            label += f"\\nLocal AS: {protocol.autonomous_system}"

                        # Add remote AS to label if available
                        if isinstance(peer_info, dict) and 'remote_as' in peer_info:
                            label += f"\\nRemote AS: {peer_info['remote_as']}"

                        style = (
                            'endArrow=classic;startArrow=classic;html=1;rounded=0;'
                            'strokeColor=#CC6600;strokeWidth=3;dashed=1;'
                        )

                        self.add_connection(root, device_id, peer_id, label, style)

                        # Move to next peer position
                        peer_y += 150

                # Draw OSPF neighbors
                if protocol.protocol == ProtocolType.OSPF and protocol.neighbors:
                    for neighbor_ip in protocol.neighbors:
                        # Draw each OSPF neighbor as separate box
                        peer_label = self._build_ospf_peer_label(neighbor_ip, protocol)
                        peer_id = self.add_router(root, f"OSPF-{neighbor_ip}", peer_x, peer_y, label_text=peer_label)

                        # Draw connection line
                        label = "OSPF Adjacency"
                        if protocol.router_id:
                            label += f"\\nRouter ID: {protocol.router_id}"

                        style = (
                            'endArrow=classic;startArrow=classic;html=1;rounded=0;'
                            'strokeColor=#0066CC;strokeWidth=3;'
                        )

                        self.add_connection(root, device_id, peer_id, label, style)

                        # Move to next peer position
                        peer_y += 150

            # Move to next device position
            current_y += device_spacing_y

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

    def _build_device_label(self, device: NetworkDevice, vr: VirtualRouter, vr_data: Dict) -> str:
        """Build label for device box"""
        label = f"{device.hostname}"

        if vr:
            label += f"\\nVR: {vr.name}"
            if vr.vsys:
                label += f"\\nVSYS: {vr.vsys}"

        # Add routing protocol info
        for protocol in vr_data['routing_protocols']:
            label += f"\\n{protocol.protocol.value.upper()}"

            if protocol.protocol == ProtocolType.BGP and protocol.autonomous_system:
                label += f" AS{protocol.autonomous_system}"

            if protocol.router_id:
                label += f"\\nRID: {protocol.router_id}"

            if protocol.protocol == ProtocolType.OSPF and protocol.areas:
                label += f"\\nAreas: {', '.join(protocol.areas[:2])}"

        return label

    def _build_bgp_peer_label(self, peer_info, protocol) -> str:
        """Build label for BGP peer box"""
        # Handle both dict and string formats
        if isinstance(peer_info, dict):
            peer_ip = peer_info.get('ip', 'Unknown')
            label = f"BGP Peer\\n{peer_ip}"

            # Add remote AS if available
            if 'remote_as' in peer_info:
                label += f"\\nAS{peer_info['remote_as']}"

            # Add description if available
            if 'description' in peer_info:
                label += f"\\n{peer_info['description']}"
        else:
            # Fallback for simple string IP
            label = f"BGP Peer\\n{peer_info}\\n(Remote)"

        return label

    def _build_ospf_peer_label(self, neighbor_ip: str, protocol) -> str:
        """Build label for OSPF neighbor box"""
        label = f"OSPF Neighbor\\n{neighbor_ip}"

        if protocol.areas:
            label += f"\\nArea: {protocol.areas[0]}"

        return label

    def _draw_legend(self, root):
        """Draw legend explaining the diagram"""
        legend_x = 100
        legend_y = 50

        legend_text = (
            "Legend:\\n"
            "━━━ OSPF Adjacency (solid blue)\\n"
            "- - - BGP Peering (dashed orange)\\n\\n"
            "Each device/VR shown with all peers\\n"
            "Every neighbor is a separate box"
        )

        self.add_text_label(root, legend_text, legend_x, legend_y, width=250, height=150)
