"""
Network Connection Diagram Generator
Shows physical and logical connections between devices
"""
from typing import List
from generators.drawio_generator import DrawIOGenerator
from models.network_models import NetworkDevice, NetworkTopology, InterfaceType


class NetworkConnectionDiagram(DrawIOGenerator):
    """Generator for network connection diagrams"""

    def generate(self, topology: NetworkTopology, filename: str):
        """Generate network connection diagram"""
        mxfile, root = self.create_diagram("Network Connection Diagram")

        # First, add all devices
        device_positions = {}
        for i, device in enumerate(topology.devices):
            x, y = self.calculate_grid_position(i, columns=3, spacing_x=300, spacing_y=250)
            device_id = self.add_device(root, device, x, y)
            device_positions[device.hostname] = (device_id, x, y)

            # Add interface information as text below device
            interface_text = self._get_interface_summary(device)
            if interface_text:
                self.add_text_label(root, interface_text, x - 50, y + 130, width=200, height=100)

        # Add connections between devices
        self._add_connections(root, topology, device_positions)

        # Save diagram
        self.save_diagram(mxfile, filename)

    def _get_interface_summary(self, device: NetworkDevice) -> str:
        """Get summary of device interfaces"""
        summary_lines = []

        # Group interfaces by type
        physical_intfs = [i for i in device.interfaces if i.type == InterfaceType.PHYSICAL and i.enabled]
        vlan_intfs = [i for i in device.interfaces if i.type == InterfaceType.VLAN and i.enabled]
        mgmt_intfs = [i for i in device.interfaces if i.type == InterfaceType.MANAGEMENT]

        # Show key interfaces
        for intf in physical_intfs[:3]:  # Show first 3 physical interfaces
            line = f"{intf.name}"
            if intf.ip_address:
                line += f": {intf.ip_address}"
            elif intf.access_vlan:
                line += f": VLAN {intf.access_vlan}"
            elif intf.trunk_vlans:
                line += ": Trunk"
            summary_lines.append(line)

        # Show management interface
        for intf in mgmt_intfs:
            if intf.ip_address:
                summary_lines.append(f"Mgmt: {intf.ip_address}")

        if len(physical_intfs) > 3:
            summary_lines.append(f"...and {len(physical_intfs) - 3} more")

        return "\n".join(summary_lines)

    def _add_connections(self, root, topology: NetworkTopology, device_positions):
        """Add connection lines between devices"""
        # Add explicit connections from topology
        for conn in topology.connections:
            device1 = conn['device1']
            interface1 = conn['interface1']
            device2 = conn['device2']
            interface2 = conn['interface2']

            if device1 in device_positions and device2 in device_positions:
                source_id = device_positions[device1][0]
                target_id = device_positions[device2][0]

                label = f"{interface1} ⟷ {interface2}"
                self.add_connection(root, source_id, target_id, label)

        # Try to infer connections based on interface configurations
        self._infer_connections(root, topology, device_positions)

    def _infer_connections(self, root, topology: NetworkTopology, device_positions):
        """Infer connections based on IP addressing and VLANs"""
        # Group devices by subnet
        subnet_map = {}

        for device in topology.devices:
            for interface in device.interfaces:
                if interface.ip_address and interface.subnet_mask:
                    subnet = self._get_subnet(interface.ip_address, interface.subnet_mask)
                    if subnet not in subnet_map:
                        subnet_map[subnet] = []
                    subnet_map[subnet].append({
                        'device': device.hostname,
                        'interface': interface.name,
                        'ip': interface.ip_address
                    })

        # Create connections for devices on same subnet
        for subnet, members in subnet_map.items():
            if len(members) > 1:
                # Connect all devices on same subnet (mesh)
                # For simplicity, connect first device to all others
                for i in range(1, len(members)):
                    device1 = members[0]['device']
                    interface1 = members[0]['interface']
                    device2 = members[i]['device']
                    interface2 = members[i]['interface']

                    # Check if connection already exists
                    if not self._connection_exists(topology, device1, device2):
                        if device1 in device_positions and device2 in device_positions:
                            source_id = device_positions[device1][0]
                            target_id = device_positions[device2][0]

                            label = f"{interface1}\\n{members[0]['ip']}\\n⟷\\n{interface2}\\n{members[i]['ip']}"
                            self.add_connection(root, source_id, target_id, label)

    def _connection_exists(self, topology: NetworkTopology, device1: str, device2: str) -> bool:
        """Check if connection already exists"""
        for conn in topology.connections:
            if (conn['device1'] == device1 and conn['device2'] == device2) or \
               (conn['device1'] == device2 and conn['device2'] == device1):
                return True
        return False

    def _get_subnet(self, ip: str, netmask: str) -> str:
        """Calculate subnet from IP and netmask"""
        ip_parts = [int(p) for p in ip.split('.')]
        mask_parts = [int(p) for p in netmask.split('.')]

        subnet_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        return '.'.join(str(p) for p in subnet_parts)
