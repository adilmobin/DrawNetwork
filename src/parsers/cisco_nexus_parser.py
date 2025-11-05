"""
Cisco Nexus Switch Configuration Parser
"""
import re
from typing import List, Optional
from models.network_models import (
    NetworkDevice, Interface, VLAN, Route, RoutingProtocol,
    DeviceType, InterfaceType, ProtocolType
)


class CiscoNexusParser:
    """Parser for Cisco Nexus switch configurations"""

    def __init__(self):
        self.current_section = None
        self.indent_stack = []

    def parse(self, config_text: str) -> NetworkDevice:
        """Parse Cisco Nexus configuration"""
        device = NetworkDevice(
            hostname="Unknown",
            device_type=DeviceType.CISCO_NEXUS
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
            elif line.startswith('ip domain-name '):
                device.domain_name = line.split('ip domain-name ')[1].strip()

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
                vlan, next_i = self._parse_vlan(lines, i)
                if vlan:
                    device.vlans.append(vlan)
                i = next_i
                continue

            # Static routes
            elif line.startswith('ip route ') or line.startswith('ipv6 route '):
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

            # Feature configurations
            elif line.startswith('feature '):
                # Track enabled features if needed
                pass

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
            if not line or line.startswith('!') or (not line.startswith(' ') and line):
                if not line.startswith(' ') and line and not line.startswith('!'):
                    break

            # IP address
            if line.startswith('ip address '):
                match = re.match(r'ip address (\S+)\/(\d+)', line)
                if match:
                    interface.ip_address = match.group(1)
                    cidr = int(match.group(2))
                    interface.subnet_mask = self._cidr_to_netmask(cidr)
                else:
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

            # VLAN (for access ports)
            elif line.startswith('switchport access vlan '):
                interface.access_vlan = int(line.split('switchport access vlan ')[1].strip())

            # Trunk VLANs
            elif line.startswith('switchport trunk allowed vlan '):
                vlan_str = line.split('switchport trunk allowed vlan ')[1].strip()
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

    def _parse_vlan(self, lines: List[str], start_idx: int) -> tuple[Optional[VLAN], int]:
        """Parse VLAN configuration block"""
        line = lines[start_idx]
        match = re.match(r'vlan\s+(\d+)', line)
        if not match:
            return None, start_idx + 1

        vlan_id = int(match.group(1))
        vlan = VLAN(vlan_id=vlan_id)

        i = start_idx + 1
        while i < len(lines):
            line = lines[i].strip()

            # End of VLAN section
            if not line or (not line.startswith(' ') and line):
                if not line.startswith(' ') and line and not line.startswith('!'):
                    break

            # VLAN name
            if line.startswith('name '):
                vlan.name = line.split('name ', 1)[1].strip()

            i += 1

        return vlan, i

    def _parse_static_route(self, line: str) -> Optional[Route]:
        """Parse static route"""
        # ip route 0.0.0.0/0 192.168.1.1
        # ip route 10.0.0.0/8 Ethernet1/1 192.168.1.1
        match = re.match(r'ip route (\S+)\/(\d+)\s+(\S+)(?:\s+(\S+))?', line)
        if match:
            destination = match.group(1)
            cidr = int(match.group(2))
            netmask = self._cidr_to_netmask(cidr)
            next_part = match.group(3)

            # Check if next_part is an interface or IP
            if self._is_ip_address(next_part):
                return Route(
                    destination=destination,
                    mask=netmask,
                    next_hop=next_part,
                    protocol=ProtocolType.STATIC
                )
            else:
                next_hop = match.group(4) if match.group(4) else None
                return Route(
                    destination=destination,
                    mask=netmask,
                    interface=next_part,
                    next_hop=next_hop,
                    protocol=ProtocolType.STATIC
                )

        return None

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

        i = start_idx + 1
        while i < len(lines):
            line = lines[i].strip()

            # End of routing protocol section
            if not line or (not line.startswith(' ') and line):
                if not line.startswith(' ') and line and not line.startswith('!'):
                    break

            # Router ID
            if line.startswith('router-id '):
                routing_protocol.router_id = line.split('router-id ')[1].strip()

            # Network statements
            elif line.startswith('network '):
                match = re.match(r'network (\S+)(?:\/(\d+))?\s*(?:area\s+(\S+))?', line)
                if match:
                    network = {
                        'network': match.group(1),
                        'mask': match.group(2) if match.group(2) else None,
                        'area': match.group(3) if match.group(3) else None
                    }
                    routing_protocol.networks.append(network)

            # Neighbor statements
            elif line.startswith('neighbor '):
                match = re.match(r'neighbor (\S+)', line)
                if match:
                    routing_protocol.neighbors.append(match.group(1))

            # Redistribute
            elif line.startswith('redistribute '):
                protocol = line.split('redistribute ')[1].split()[0]
                routing_protocol.redistributed_protocols.append(protocol)

            i += 1

        return routing_protocol, i

    def _determine_interface_type(self, name: str) -> InterfaceType:
        """Determine interface type from name"""
        name_lower = name.lower()
        if 'ethernet' in name_lower or 'eth' in name_lower:
            return InterfaceType.PHYSICAL
        elif 'vlan' in name_lower:
            return InterfaceType.VLAN
        elif 'loopback' in name_lower:
            return InterfaceType.LOOPBACK
        elif 'mgmt' in name_lower or 'management' in name_lower:
            return InterfaceType.MANAGEMENT
        elif 'port-channel' in name_lower or 'po' in name_lower:
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
                vlans.append(int(part))
        return vlans

    def _cidr_to_netmask(self, cidr: int) -> str:
        """Convert CIDR to netmask"""
        mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"

    def _is_ip_address(self, text: str) -> bool:
        """Check if text is an IP address"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return re.match(pattern, text) is not None
