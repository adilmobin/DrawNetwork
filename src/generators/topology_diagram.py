"""
Topology Diagram Generator
Shows physical network topology with hierarchical layout
"""
from typing import Dict, List, Set, Tuple
from generators.drawio_generator import DrawIOGenerator
from models.network_models import NetworkDevice, NetworkTopology, DeviceType, InterfaceType


class TopologyDiagram(DrawIOGenerator):
    """Generator for network topology diagrams"""

    def generate(self, topology: NetworkTopology, filename: str):
        """Generate topology diagram with hierarchical layout"""
        mxfile, root = self.create_diagram("Network Topology")

        # Classify devices into layers
        layers = self._classify_devices_into_layers(topology)

        # Draw devices layer by layer
        device_positions = self._draw_layered_topology(root, layers)

        # Add connections
        self._add_topology_connections(root, topology, device_positions)

        # Add Internet/WAN cloud if there are default routes
        self._add_wan_cloud(root, topology, device_positions)

        # Save diagram
        self.save_diagram(mxfile, filename)

    def _classify_devices_into_layers(self, topology: NetworkTopology) -> Dict[str, List[NetworkDevice]]:
        """Classify devices into network layers (Core, Distribution, Access, DMZ, etc.)"""
        layers = {
            'wan': [],      # WAN routers / Edge firewalls
            'core': [],     # Core switches/routers
            'distribution': [],  # Distribution layer
            'access': [],   # Access layer switches
            'firewall': [], # Firewalls
            'other': []     # Other devices
        }

        for device in topology.devices:
            # Firewalls go to firewall layer
            if device.device_type in [DeviceType.CISCO_ASA, DeviceType.PALO_ALTO]:
                layers['firewall'].append(device)

            # Devices with default routes are likely edge/WAN devices
            elif self._has_default_route(device):
                layers['wan'].append(device)

            # Devices with routing protocols are likely core
            elif device.routing_protocols:
                layers['core'].append(device)

            # Devices with many VLANs are likely distribution
            elif len(device.vlans) > 10:
                layers['distribution'].append(device)

            # Switches with few VLANs are access layer
            elif device.device_type in [DeviceType.CISCO_NEXUS, DeviceType.CISCO_CATALYST]:
                if len(device.vlans) > 0:
                    layers['access'].append(device)
                else:
                    layers['access'].append(device)

            else:
                layers['other'].append(device)

        # If no clear layering, put everything in core
        if not any(layers[k] for k in ['wan', 'core', 'distribution', 'access', 'firewall']):
            layers['core'] = topology.devices

        return layers

    def _draw_layered_topology(self, root, layers: Dict[str, List[NetworkDevice]]) -> Dict[str, Tuple]:
        """Draw devices in hierarchical layers"""
        device_positions = {}
        y_spacing = 250
        y = 100

        # Define layer order (top to bottom)
        layer_order = ['wan', 'firewall', 'core', 'distribution', 'access', 'other']

        for layer_name in layer_order:
            devices = layers[layer_name]
            if not devices:
                continue

            # Add layer label
            label_text = f"--- {layer_name.upper()} LAYER ---"
            self.add_text_label(root, label_text, 50, y - 30, width=300, height=30)

            # Calculate X positions for devices in this layer
            x_spacing = 250
            total_width = len(devices) * x_spacing
            x_start = max(100, (1200 - total_width) // 2)  # Center devices

            # Draw devices
            for i, device in enumerate(devices):
                x = x_start + i * x_spacing

                # Choose appropriate icon
                if device.device_type in [DeviceType.CISCO_ASA, DeviceType.PALO_ALTO]:
                    device_id = self.add_firewall(root, device.hostname, x, y)
                elif device.device_type in [DeviceType.CISCO_NEXUS, DeviceType.CISCO_CATALYST]:
                    device_id = self.add_switch(root, device.hostname, x, y)
                else:
                    device_id = self.add_router(root, device.hostname, x, y)

                device_positions[device.hostname] = (device_id, x, y)

                # Add device info below icon
                info_text = self._get_device_info(device)
                if info_text:
                    self.add_text_label(root, info_text, x - 20, y + 110, width=140, height=80)

            y += y_spacing

        return device_positions

    def _add_topology_connections(self, root, topology: NetworkTopology, device_positions: Dict):
        """Add connections between devices"""
        # Add explicit connections
        for conn in topology.connections:
            device1 = conn['device1']
            device2 = conn['device2']

            if device1 in device_positions and device2 in device_positions:
                source_id = device_positions[device1][0]
                target_id = device_positions[device2][0]

                label = f"{conn['interface1']}\\n⟷\\n{conn['interface2']}"
                self.add_connection(root, source_id, target_id, label)

        # Infer connections based on subnets
        self._infer_topology_connections(root, topology, device_positions)

    def _infer_topology_connections(self, root, topology: NetworkTopology, device_positions: Dict):
        """Infer connections based on IP subnets"""
        # Build subnet map
        subnet_map = {}

        for device in topology.devices:
            for interface in device.interfaces:
                if interface.ip_address and interface.subnet_mask and interface.enabled:
                    subnet = self._calculate_subnet(interface.ip_address, interface.subnet_mask)
                    if subnet not in subnet_map:
                        subnet_map[subnet] = []
                    subnet_map[subnet].append({
                        'device': device.hostname,
                        'interface': interface.name,
                        'ip': interface.ip_address
                    })

        # Create connections for devices on same subnet
        for subnet, members in subnet_map.items():
            if len(members) == 2:
                # Point-to-point connection
                device1 = members[0]['device']
                device2 = members[1]['device']

                if not self._connection_exists(topology, device1, device2):
                    if device1 in device_positions and device2 in device_positions:
                        source_id = device_positions[device1][0]
                        target_id = device_positions[device2][0]

                        label = f"{members[0]['interface']} ({members[0]['ip']})\\n⟷\\n{members[1]['interface']} ({members[1]['ip']})"
                        self.add_connection(root, source_id, target_id, label)

            elif len(members) > 2:
                # Shared network segment
                # Connect first device to all others (star topology)
                for i in range(1, len(members)):
                    device1 = members[0]['device']
                    device2 = members[i]['device']

                    if not self._connection_exists(topology, device1, device2):
                        if device1 in device_positions and device2 in device_positions:
                            source_id = device_positions[device1][0]
                            target_id = device_positions[device2][0]

                            label = f"Subnet: {subnet}"
                            self.add_connection(root, source_id, target_id, label)

    def _add_wan_cloud(self, root, topology: NetworkTopology, device_positions: Dict):
        """Add WAN/Internet cloud if devices have default routes"""
        # Find devices with default routes
        edge_devices = []

        for device in topology.devices:
            if self._has_default_route(device):
                edge_devices.append(device)

        if edge_devices:
            # Add cloud at the top
            cloud_id = self.add_cloud(root, "Internet / WAN", 500, 20, label_text="Internet")

            # Connect cloud to edge devices
            for device in edge_devices:
                if device.hostname in device_positions:
                    target_id = device_positions[device.hostname][0]

                    # Find the default route next hop
                    next_hop = None
                    for route in device.routes:
                        if route.destination in ['0.0.0.0', '0.0.0.0/0', '::/0']:
                            next_hop = route.next_hop or route.interface
                            break

                    label = f"Default Route"
                    if next_hop:
                        label += f"\\nvia {next_hop}"

                    style = (
                        'endArrow=classic;html=1;rounded=0;'
                        'strokeColor=#CC0000;strokeWidth=3;dashed=1;'
                    )

                    self.add_connection(root, cloud_id, target_id, label, style)

    def _get_device_info(self, device: NetworkDevice) -> str:
        """Get device information for label"""
        info = []

        # Management IP
        if device.management_ip:
            info.append(f"Mgmt: {device.management_ip}")

        # Count of interfaces
        active_intfs = [i for i in device.interfaces if i.enabled]
        if active_intfs:
            info.append(f"Interfaces: {len(active_intfs)}")

        # VLANs for switches
        if device.vlans:
            info.append(f"VLANs: {len(device.vlans)}")

        # Routing protocols
        if device.routing_protocols:
            protocols = [p.protocol.value for p in device.routing_protocols]
            info.append(f"Routing: {', '.join(protocols)}")

        return "\n".join(info)

    def _has_default_route(self, device: NetworkDevice) -> bool:
        """Check if device has a default route"""
        for route in device.routes:
            if route.destination in ['0.0.0.0', '0.0.0.0/0', '::/0']:
                return True
        return False

    def _calculate_subnet(self, ip: str, netmask: str) -> str:
        """Calculate subnet from IP and netmask"""
        try:
            ip_parts = [int(p) for p in ip.split('.')]
            mask_parts = [int(p) for p in netmask.split('.')]
            subnet_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            return '.'.join(str(p) for p in subnet_parts) + '/' + str(self._netmask_to_cidr(netmask))
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

    def _connection_exists(self, topology: NetworkTopology, device1: str, device2: str) -> bool:
        """Check if connection already exists"""
        for conn in topology.connections:
            if (conn['device1'] == device1 and conn['device2'] == device2) or \
               (conn['device1'] == device2 and conn['device2'] == device1):
                return True
        return False
