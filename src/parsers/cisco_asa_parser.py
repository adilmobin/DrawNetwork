"""
Cisco ASA Firewall Configuration Parser
"""
import re
from typing import List, Optional
from models.network_models import (
    NetworkDevice, Interface, SecurityZone, SecurityPolicy, NAT, VPN, Route,
    DeviceType, InterfaceType, ProtocolType
)


class CiscoASAParser:
    """Parser for Cisco ASA firewall configurations"""

    def __init__(self):
        self.object_groups = {}
        self.network_objects = {}

    def parse(self, config_text: str) -> NetworkDevice:
        """Parse Cisco ASA configuration"""
        device = NetworkDevice(
            hostname="Unknown",
            device_type=DeviceType.CISCO_ASA
        )

        lines = config_text.split('\n')

        # First pass: collect object definitions
        self._parse_objects(lines)

        # Second pass: parse configuration
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
            elif line.startswith('domain-name '):
                device.domain_name = line.split('domain-name ')[1].strip()

            # Interface configuration
            elif line.startswith('interface '):
                interface, next_i = self._parse_interface(lines, i)
                if interface:
                    device.interfaces.append(interface)
                    # Check if this interface is part of a security zone
                    if hasattr(interface, 'security_level'):
                        zone = self._get_or_create_zone(interface.name, interface.security_level)
                        device.security_zones.append(zone)
                i = next_i
                continue

            # Static routes
            elif line.startswith('route '):
                route = self._parse_route(line)
                if route:
                    device.routes.append(route)

            # Access lists (security policies)
            elif line.startswith('access-list '):
                policy = self._parse_access_list(line)
                if policy:
                    device.security_policies.append(policy)

            # NAT configuration
            elif line.startswith('nat ') or line.startswith('static ') or line.startswith('global '):
                nat = self._parse_nat(line)
                if nat:
                    device.nat_rules.append(nat)

            # Object NAT
            elif line.startswith('object network '):
                nat, next_i = self._parse_object_nat(lines, i)
                if nat:
                    device.nat_rules.append(nat)
                i = next_i
                continue

            # VPN configuration
            elif line.startswith('crypto map '):
                vpn, next_i = self._parse_crypto_map(lines, i)
                if vpn:
                    device.vpn_configs.append(vpn)
                i = next_i
                continue

            # Tunnel group (VPN)
            elif line.startswith('tunnel-group '):
                vpn, next_i = self._parse_tunnel_group(lines, i)
                if vpn:
                    # Merge with existing VPN config if it exists
                    existing = next((v for v in device.vpn_configs if v.name == vpn.name), None)
                    if existing:
                        if vpn.peer:
                            existing.peer = vpn.peer
                        if vpn.authentication:
                            existing.authentication = vpn.authentication
                    else:
                        device.vpn_configs.append(vpn)
                i = next_i
                continue

            i += 1

        return device

    def _parse_objects(self, lines: List[str]):
        """First pass to parse object definitions"""
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Network object
            if line.startswith('object network '):
                obj_name = line.split('object network ')[1].strip()
                i += 1
                while i < len(lines):
                    subline = lines[i].strip()
                    if subline.startswith('host '):
                        self.network_objects[obj_name] = subline.split('host ')[1].strip()
                        break
                    elif subline.startswith('subnet '):
                        parts = subline.split()
                        if len(parts) >= 3:
                            self.network_objects[obj_name] = f"{parts[1]}/{parts[2]}"
                        break
                    elif not subline.startswith(' ') and subline:
                        break
                    i += 1

            # Object-group
            elif line.startswith('object-group '):
                match = re.match(r'object-group\s+(\S+)\s+(\S+)', line)
                if match:
                    group_type = match.group(1)
                    group_name = match.group(2)
                    self.object_groups[group_name] = {'type': group_type, 'members': []}

                    i += 1
                    while i < len(lines):
                        subline = lines[i].strip()
                        if subline.startswith('network-object '):
                            member = subline.split('network-object ')[1].strip()
                            self.object_groups[group_name]['members'].append(member)
                        elif subline.startswith('group-object '):
                            member = subline.split('group-object ')[1].strip()
                            self.object_groups[group_name]['members'].append(member)
                        elif not subline.startswith(' ') and subline:
                            break
                        i += 1
                    continue

            i += 1

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
        security_level = None

        while i < len(lines):
            line = lines[i].strip()

            # End of interface section
            if not line.startswith(' ') and line and not line.startswith('!'):
                break

            # Nameif (security zone name)
            if line.startswith('nameif '):
                zone_name = line.split('nameif ')[1].strip()
                # Store zone name in description for now
                interface.description = f"Zone: {zone_name}"

            # Security level
            elif line.startswith('security-level '):
                security_level = int(line.split('security-level ')[1].strip())
                interface.security_level = security_level

            # IP address
            elif line.startswith('ip address '):
                match = re.match(r'ip address (\S+)\s+(\S+)', line)
                if match:
                    interface.ip_address = match.group(1)
                    interface.subnet_mask = match.group(2)

            # Shutdown status
            elif line.strip() == 'shutdown':
                interface.enabled = False
            elif line.strip() == 'no shutdown':
                interface.enabled = True

            # VLAN
            elif line.startswith('vlan '):
                interface.vlan = int(line.split('vlan ')[1].strip())

            i += 1

        return interface, i

    def _parse_route(self, line: str) -> Optional[Route]:
        """Parse static route"""
        # route outside 0.0.0.0 0.0.0.0 192.168.1.1 1
        parts = line.split()
        if len(parts) < 5:
            return None

        interface = parts[1]
        destination = parts[2]
        netmask = parts[3]
        next_hop = parts[4]

        ad = None
        if len(parts) > 5:
            try:
                ad = int(parts[5])
            except ValueError:
                pass

        return Route(
            destination=destination,
            mask=netmask,
            next_hop=next_hop,
            interface=interface,
            protocol=ProtocolType.STATIC,
            administrative_distance=ad
        )

    def _parse_access_list(self, line: str) -> Optional[SecurityPolicy]:
        """Parse access-list entry"""
        # access-list outside_in extended permit tcp any host 10.0.0.5 eq 443
        # access-list inside_out extended permit ip any any

        match = re.match(
            r'access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(\S+)\s+(.+)',
            line
        )
        if not match:
            return None

        acl_name = match.group(1)
        action = match.group(2)
        protocol = match.group(3)
        rest = match.group(4)

        parts = rest.split()

        # Parse source
        source = []
        dest = []
        service = [protocol]

        idx = 0
        # Source address
        if idx < len(parts):
            if parts[idx] == 'any':
                source.append('any')
                idx += 1
            elif parts[idx] == 'host' and idx + 1 < len(parts):
                source.append(parts[idx + 1])
                idx += 2
            elif idx + 1 < len(parts):
                source.append(f"{parts[idx]} {parts[idx + 1]}")
                idx += 2

        # Destination address
        if idx < len(parts):
            if parts[idx] == 'any':
                dest.append('any')
                idx += 1
            elif parts[idx] == 'host' and idx + 1 < len(parts):
                dest.append(parts[idx + 1])
                idx += 2
            elif idx + 1 < len(parts):
                dest.append(f"{parts[idx]} {parts[idx + 1]}")
                idx += 2

        # Service/port
        if idx < len(parts) and parts[idx] == 'eq':
            if idx + 1 < len(parts):
                service.append(f"eq {parts[idx + 1]}")

        return SecurityPolicy(
            name=acl_name,
            source_address=source,
            destination_address=dest,
            service=service,
            action=action
        )

    def _parse_nat(self, line: str) -> Optional[NAT]:
        """Parse NAT configuration"""
        # nat (inside,outside) source dynamic any interface
        # static (inside,outside) 192.168.1.5 10.0.0.5

        if line.startswith('nat ('):
            match = re.match(r'nat\s+\((\S+),(\S+)\)\s+(.+)', line)
            if match:
                src_intf = match.group(1)
                dst_intf = match.group(2)
                rest = match.group(3)

                return NAT(
                    type='dynamic',
                    source_interface=src_intf,
                    destination_interface=dst_intf,
                    original_source=rest
                )

        elif line.startswith('static ('):
            match = re.match(r'static\s+\((\S+),(\S+)\)\s+(\S+)\s+(\S+)', line)
            if match:
                return NAT(
                    type='static',
                    source_interface=match.group(1),
                    destination_interface=match.group(2),
                    translated_source=match.group(3),
                    original_source=match.group(4)
                )

        return None

    def _parse_object_nat(self, lines: List[str], start_idx: int) -> tuple[Optional[NAT], int]:
        """Parse object NAT configuration"""
        line = lines[start_idx]
        match = re.match(r'object network\s+(\S+)', line)
        if not match:
            return None, start_idx + 1

        obj_name = match.group(1)
        nat_config = None

        i = start_idx + 1
        while i < len(lines):
            line = lines[i].strip()

            if not line.startswith(' ') and line and not line.startswith('!'):
                break

            # NAT statement
            if line.startswith('nat ('):
                match = re.match(r'nat\s+\((\S+),(\S+)\)\s+(\S+)', line)
                if match:
                    nat_config = NAT(
                        type=match.group(3),
                        source_interface=match.group(1),
                        destination_interface=match.group(2),
                        original_source=obj_name
                    )

            i += 1

        return nat_config, i

    def _parse_crypto_map(self, lines: List[str], start_idx: int) -> tuple[Optional[VPN], int]:
        """Parse crypto map (VPN) configuration"""
        line = lines[start_idx]
        match = re.match(r'crypto map\s+(\S+)\s+(\d+)', line)
        if not match:
            return None, start_idx + 1

        map_name = match.group(1)
        sequence = match.group(2)

        vpn = VPN(
            name=f"{map_name}_{sequence}",
            type='ipsec'
        )

        # Parse the rest of the line
        if 'set peer' in line:
            peer = line.split('set peer')[1].strip()
            vpn.peer = peer

        if 'match address' in line:
            acl = line.split('match address')[1].strip()
            # ACL would define interesting traffic

        return vpn, start_idx + 1

    def _parse_tunnel_group(self, lines: List[str], start_idx: int) -> tuple[Optional[VPN], int]:
        """Parse tunnel-group configuration"""
        line = lines[start_idx]
        match = re.match(r'tunnel-group\s+(\S+)\s+type\s+(\S+)', line)
        if not match:
            return None, start_idx + 1

        peer = match.group(1)
        vpn_type = match.group(2)

        vpn = VPN(
            name=peer,
            type=vpn_type,
            peer=peer
        )

        i = start_idx + 1
        while i < len(lines):
            line = lines[i].strip()

            if not line.startswith(' ') and line and not line.startswith('!'):
                break

            # Authentication
            if 'authentication-server-group' in line or 'pre-shared-key' in line:
                vpn.authentication = 'pre-shared-key'

            i += 1

        return vpn, i

    def _get_or_create_zone(self, interface_name: str, security_level: int) -> SecurityZone:
        """Get or create security zone"""
        zone_name = f"zone_{security_level}"
        return SecurityZone(
            name=zone_name,
            interfaces=[interface_name],
            security_level=security_level
        )

    def _determine_interface_type(self, name: str) -> InterfaceType:
        """Determine interface type from name"""
        name_lower = name.lower()
        if 'gigabitethernet' in name_lower or 'ethernet' in name_lower:
            return InterfaceType.PHYSICAL
        elif 'vlan' in name_lower:
            return InterfaceType.VLAN
        elif 'management' in name_lower:
            return InterfaceType.MANAGEMENT
        elif 'tunnel' in name_lower:
            return InterfaceType.TUNNEL
        else:
            return InterfaceType.PHYSICAL
