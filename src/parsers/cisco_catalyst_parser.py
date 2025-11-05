"""
Cisco Catalyst Switch Configuration Parser
"""
import re
from typing import List, Optional
from models.network_models import (
    NetworkDevice, Interface, VLAN, Route, RoutingProtocol,
    DeviceType, InterfaceType, ProtocolType
)


class CiscoCatalystParser:
    """Parser for Cisco Catalyst switch configurations"""

    def __init__(self):
        self.current_section = None

    def parse(self, config_text: str) -> NetworkDevice:
        """Parse Cisco Catalyst configuration"""
        device = NetworkDevice(
            hostname="Unknown",
            device_type=DeviceType.CISCO_CATALYST
        )

        lines = config_text.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].rstrip()

            # Skip empty lines and comments
            if not line or line.startswith('!'):
                i += 1
                continue

            # Hostname
            if line.startswith('hostname '):
                device.hostname = line.split('hostname ')[1].strip()

            # Domain name
            elif line.startswith('ip domain name ') or line.startswith('ip domain-name '):
                device.domain_name = re.split(r'ip domain[- ]name ', line)[1].strip()

            # Version
            elif line.startswith('version '):
                device.software_version = line.split('version ')[1].strip()

            # Interface configuration
            elif line.startswith('interface '):
                interface, next_i = self._parse_interface(lines, i)
                if interface:
                    device.interfaces.append(interface)
                i = next_i
                continue

            # VLAN configuration
            elif line.startswith('vlan '):
                vlans, next_i = self._parse_vlan_block(lines, i)
                device.vlans.extend(vlans)
                i = next_i
                continue

            # Static routes
            elif line.startswith('ip route '):
                route = self._parse_static_route(line)
                if route:
                    device.routes.append(route)

            # Routing protocols
            elif line.startswith('router '):
                protocol, next_i = self._parse_routing_protocol(lines, i)
                if protocol:
                    device.routing_protocols.append(protocol)
                i = next_i
                continue

            i += 1

        return device

    def _parse_interface(self, lines: List[str], start_idx: int) -> tuple[Optional[Interface], int]:
        """Parse interface configuration block"""
        line = lines[start_idx]
        match = re.match(r'interface\s+(\S+)', line)
        if not match:
            return None, start_idx + 1

        interface_name = match.group(1)
        interface = Interface(
            name=interface_name,
            type=self._determine_interface_type(interface_name)
        )

        i = start_idx + 1
        while i < len(lines):
            line = lines[i].strip()

            # End of interface section
            if not line.startswith(' ') and line and not line.startswith('!'):
                break

            # IP address
            if line.startswith('ip address '):
                match = re.match(r'ip address (\S+)\s+(\S+)', line)
                if match:
                    interface.ip_address = match.group(1)
                    interface.subnet_mask = match.group(2)

            # Description
            elif line.startswith('description '):
                interface.description = line.split('description ', 1)[1].strip()

            # Shutdown status
            elif line.strip() == 'shutdown':
                interface.enabled = False
            elif line.strip() == 'no shutdown':
                interface.enabled = True

            # Speed
            elif line.startswith('speed '):
                interface.speed = line.split('speed ')[1].strip()

            # Duplex
            elif line.startswith('duplex '):
                interface.duplex = line.split('duplex ')[1].strip()

            # Switchport mode
            elif line.startswith('switchport mode '):
                mode = line.split('switchport mode ')[1].strip()
                # Mode can be access, trunk, dynamic, etc.

            # VLAN (for access ports)
            elif line.startswith('switchport access vlan '):
                interface.access_vlan = int(line.split('switchport access vlan ')[1].strip())

            # Trunk VLANs
            elif line.startswith('switchport trunk allowed vlan '):
                vlan_str = line.split('switchport trunk allowed vlan ')[1].strip()
                if vlan_str != 'all':
                    interface.trunk_vlans = self._parse_vlan_list(vlan_str)

            # Native VLAN
            elif line.startswith('switchport trunk native vlan '):
                interface.native_vlan = int(line.split('switchport trunk native vlan ')[1].strip())

            # Channel group
            elif line.startswith('channel-group '):
                match = re.match(r'channel-group (\d+)', line)
                if match:
                    interface.channel_group = int(match.group(1))

            # MTU
            elif line.startswith('mtu '):
                interface.mtu = int(line.split('mtu ')[1].strip())

            # MAC address
            elif line.startswith('mac-address '):
                interface.mac_address = line.split('mac-address ')[1].strip()

            i += 1

        return interface, i

    def _parse_vlan_block(self, lines: List[str], start_idx: int) -> tuple[List[VLAN], int]:
        """Parse VLAN configuration block"""
        vlans = []
        line = lines[start_idx]

        # Handle single VLAN definition: vlan 10
        # Handle range: vlan 10,20,30-40
        match = re.match(r'vlan\s+(.+)', line)
        if not match:
            return vlans, start_idx + 1

        vlan_spec = match.group(1).strip()
        vlan_ids = self._parse_vlan_list(vlan_spec)

        # Create VLAN objects
        for vlan_id in vlan_ids:
            vlans.append(VLAN(vlan_id=vlan_id))

        i = start_idx + 1
        current_vlan = vlans[0] if vlans else None

        while i < len(lines):
            line = lines[i].strip()

            # End of VLAN section
            if not line.startswith(' ') and line and not line.startswith('!'):
                break

            # VLAN name
            if line.startswith('name ') and current_vlan:
                current_vlan.name = line.split('name ', 1)[1].strip()

            i += 1

        return vlans, i

    def _parse_static_route(self, line: str) -> Optional[Route]:
        """Parse static route"""
        # ip route 0.0.0.0 0.0.0.0 192.168.1.1
        # ip route 10.0.0.0 255.0.0.0 GigabitEthernet0/1 192.168.1.1
        parts = line.split()
        if len(parts) < 5:
            return None

        destination = parts[2]
        netmask = parts[3]
        next_part = parts[4]

        # Check if next_part is an interface or IP
        if self._is_ip_address(next_part):
            return Route(
                destination=destination,
                mask=netmask,
                next_hop=next_part,
                protocol=ProtocolType.STATIC
            )
        else:
            next_hop = parts[5] if len(parts) > 5 else None
            return Route(
                destination=destination,
                mask=netmask,
                interface=next_part,
                next_hop=next_hop,
                protocol=ProtocolType.STATIC
            )

    def _parse_routing_protocol(self, lines: List[str], start_idx: int) -> tuple[Optional[RoutingProtocol], int]:
        """Parse routing protocol configuration"""
        line = lines[start_idx]
        match = re.match(r'router\s+(\w+)\s*(\S*)', line)
        if not match:
            return None, start_idx + 1

        protocol_name = match.group(1).lower()
        process_id = match.group(2) if match.group(2) else None

        protocol_type = None
        if 'ospf' in protocol_name:
            protocol_type = ProtocolType.OSPF
        elif 'eigrp' in protocol_name:
            protocol_type = ProtocolType.EIGRP
        elif 'bgp' in protocol_name:
            protocol_type = ProtocolType.BGP
        elif 'rip' in protocol_name:
            protocol_type = ProtocolType.RIP
        elif 'isis' in protocol_name:
            protocol_type = ProtocolType.ISIS

        if not protocol_type:
            return None, start_idx + 1

        routing_protocol = RoutingProtocol(
            protocol=protocol_type,
            process_id=process_id
        )

        if protocol_type == ProtocolType.BGP:
            routing_protocol.autonomous_system = int(process_id) if process_id else None

        i = start_idx + 1
        while i < len(lines):
            line = lines[i].strip()

            # End of routing protocol section
            if not line.startswith(' ') and line and not line.startswith('!'):
                break

            # Router ID
            if line.startswith('router-id '):
                routing_protocol.router_id = line.split('router-id ')[1].strip()

            # Network statements
            elif line.startswith('network '):
                parts = line.split()
                if len(parts) >= 2:
                    network = {'network': parts[1]}
                    if len(parts) >= 4 and parts[2] == 'mask':
                        network['mask'] = parts[3]
                    if 'area' in parts:
                        area_idx = parts.index('area')
                        if area_idx + 1 < len(parts):
                            network['area'] = parts[area_idx + 1]
                    routing_protocol.networks.append(network)

            # Neighbor statements
            elif line.startswith('neighbor '):
                parts = line.split()
                if len(parts) >= 2:
                    routing_protocol.neighbors.append(parts[1])

            # Redistribute
            elif line.startswith('redistribute '):
                protocol = line.split('redistribute ')[1].split()[0]
                routing_protocol.redistributed_protocols.append(protocol)

            i += 1

        return routing_protocol, i

    def _determine_interface_type(self, name: str) -> InterfaceType:
        """Determine interface type from name"""
        name_lower = name.lower()
        if 'gigabitethernet' in name_lower or 'fastethernet' in name_lower or 'ethernet' in name_lower:
            return InterfaceType.PHYSICAL
        elif 'vlan' in name_lower:
            return InterfaceType.VLAN
        elif 'loopback' in name_lower:
            return InterfaceType.LOOPBACK
        elif 'port-channel' in name_lower:
            return InterfaceType.PORT_CHANNEL
        elif 'tunnel' in name_lower:
            return InterfaceType.TUNNEL
        else:
            return InterfaceType.PHYSICAL

    def _parse_vlan_list(self, vlan_str: str) -> List[int]:
        """Parse VLAN list (e.g., '1,2,3,10-20')"""
        vlans = []
        parts = vlan_str.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                vlans.extend(range(int(start), int(end) + 1))
            else:
                try:
                    vlans.append(int(part))
                except ValueError:
                    pass
        return vlans

    def _is_ip_address(self, text: str) -> bool:
        """Check if text is an IP address"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return re.match(pattern, text) is not None
