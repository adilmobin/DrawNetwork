"""
Logical Diagram Generator
Shows VLANs, security zones, and logical network segmentation
"""
from typing import Dict, List, Set
from generators.drawio_generator import DrawIOGenerator
from models.network_models import NetworkDevice, NetworkTopology, DeviceType


class LogicalDiagram(DrawIOGenerator):
    """Generator for logical network diagrams"""

    def generate(self, topology: NetworkTopology, filename: str):
        """Generate logical diagram"""
        mxfile, root = self.create_diagram("Logical Network Diagram")

        # Collect all VLANs and security zones
        vlans = self._collect_vlans(topology)
        zones = self._collect_security_zones(topology)

        # Layout strategy: zones on left, VLANs on right
        y_offset = 100

        # Draw security zones (for firewalls)
        if zones:
            zone_boxes = self._draw_security_zones(root, zones, topology, 100, y_offset)
            y_offset += len(zones) * 250 + 100

        # Draw VLANs (for switches)
        if vlans:
            vlan_boxes = self._draw_vlans(root, vlans, topology, 100, y_offset)

        # Draw inter-zone/VLAN connections
        self._draw_logical_connections(root, topology)

        # Save diagram
        self.save_diagram(mxfile, filename)

    def _collect_vlans(self, topology: NetworkTopology) -> Dict[int, Dict]:
        """Collect all VLANs from devices"""
        vlans = {}

        for device in topology.devices:
            for vlan in device.vlans:
                if vlan.vlan_id not in vlans:
                    vlans[vlan.vlan_id] = {
                        'id': vlan.vlan_id,
                        'name': vlan.name or f"VLAN {vlan.vlan_id}",
                        'devices': [],
                        'interfaces': []
                    }

                vlans[vlan.vlan_id]['devices'].append(device.hostname)

            # Also collect VLANs from interface configurations
            for interface in device.interfaces:
                if interface.access_vlan:
                    if interface.access_vlan not in vlans:
                        vlans[interface.access_vlan] = {
                            'id': interface.access_vlan,
                            'name': f"VLAN {interface.access_vlan}",
                            'devices': [],
                            'interfaces': []
                        }
                    vlans[interface.access_vlan]['interfaces'].append({
                        'device': device.hostname,
                        'interface': interface.name,
                        'ip': interface.ip_address
                    })

        return vlans

    def _collect_security_zones(self, topology: NetworkTopology) -> Dict[str, Dict]:
        """Collect all security zones from firewalls"""
        zones = {}

        for device in topology.devices:
            if device.device_type in [DeviceType.CISCO_ASA, DeviceType.PALO_ALTO]:
                for zone in device.security_zones:
                    zone_key = f"{device.hostname}_{zone.name}"
                    zones[zone_key] = {
                        'name': zone.name,
                        'device': device.hostname,
                        'interfaces': zone.interfaces,
                        'security_level': zone.security_level,
                        'policies': []
                    }

                # Add policies to zones
                for policy in device.security_policies:
                    if policy.source_zone:
                        src_key = f"{device.hostname}_{policy.source_zone}"
                        if src_key in zones:
                            zones[src_key]['policies'].append(policy)

        return zones

    def _draw_security_zones(self, root, zones: Dict, topology: NetworkTopology,
                            x_start: int, y_start: int) -> Dict:
        """Draw security zones as containers"""
        zone_boxes = {}
        y = y_start

        for zone_key, zone_data in zones.items():
            # Create zone container
            zone_name = f"{zone_data['name']}"
            if zone_data.get('security_level') is not None:
                zone_name += f" (Level {zone_data['security_level']})"

            zone_id = self.add_network_segment(root, zone_name, x_start, y, width=400, height=200)
            zone_boxes[zone_key] = (zone_id, x_start, y)

            # Add device in zone
            device = topology.get_device(zone_data['device'])
            if device:
                device_id = self.add_firewall(
                    root,
                    device.hostname,
                    x_start + 20,
                    y + 40,
                    label_text=device.hostname
                )

            # Add interfaces in zone
            intf_text = f"Interfaces:\n" + "\n".join(zone_data['interfaces'][:5])
            if len(zone_data['interfaces']) > 5:
                intf_text += f"\n...and {len(zone_data['interfaces']) - 5} more"

            self.add_text_label(root, intf_text, x_start + 220, y + 40, width=160, height=140)

            y += 250

        return zone_boxes

    def _draw_vlans(self, root, vlans: Dict, topology: NetworkTopology,
                   x_start: int, y_start: int) -> Dict:
        """Draw VLANs as containers"""
        vlan_boxes = {}
        y = y_start

        # Sort VLANs by ID
        sorted_vlans = sorted(vlans.items(), key=lambda x: x[0])

        for vlan_id, vlan_data in sorted_vlans:
            # Create VLAN container
            vlan_name = f"VLAN {vlan_id}"
            if vlan_data['name'] and vlan_data['name'] != vlan_name:
                vlan_name += f" - {vlan_data['name']}"

            vlan_box_id = self.add_network_segment(root, vlan_name, x_start, y, width=500, height=180)
            vlan_boxes[vlan_id] = (vlan_box_id, x_start, y)

            # Add devices in VLAN
            x_device = x_start + 20
            for i, device_name in enumerate(vlan_data['devices'][:3]):  # Show max 3 devices
                device = topology.get_device(device_name)
                if device:
                    device_id = self.add_switch(
                        root,
                        device_name,
                        x_device,
                        y + 40,
                        label_text=device_name
                    )
                    x_device += 120

            # Add interface information
            if vlan_data['interfaces']:
                intf_text = "Interfaces:\n"
                for intf_info in vlan_data['interfaces'][:4]:
                    intf_text += f"{intf_info['device']}: {intf_info['interface']}"
                    if intf_info.get('ip'):
                        intf_text += f" ({intf_info['ip']})"
                    intf_text += "\n"

                if len(vlan_data['interfaces']) > 4:
                    intf_text += f"...and {len(vlan_data['interfaces']) - 4} more"

                self.add_text_label(root, intf_text, x_start + 320, y + 40, width=160, height=120)

            y += 200

        return vlan_boxes

    def _draw_logical_connections(self, root, topology: NetworkTopology):
        """Draw logical connections between zones and VLANs"""
        # For firewalls, draw policy flows between zones
        for device in topology.devices:
            if device.device_type in [DeviceType.CISCO_ASA, DeviceType.PALO_ALTO]:
                for policy in device.security_policies:
                    if policy.source_zone and policy.destination_zone:
                        src_key = f"{device.hostname}_{policy.source_zone}"
                        dst_key = f"{device.hostname}_{policy.destination_zone}"

                        if src_key in self.cell_map and dst_key in self.cell_map:
                            label = f"{policy.action}\\n{policy.name}"
                            style = 'endArrow=classic;html=1;rounded=0;strokeColor='

                            if policy.action == 'allow' or policy.action == 'permit':
                                style += '#00CC00;strokeWidth=2;'
                            else:
                                style += '#CC0000;strokeWidth=2;dashed=1;'

                            self.add_connection(
                                root,
                                self.cell_map[src_key],
                                self.cell_map[dst_key],
                                label,
                                style
                            )
