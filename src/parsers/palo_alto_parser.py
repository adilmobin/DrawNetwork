"""
Enhanced Palo Alto Firewall/Panorama Configuration Parser
Supports NGFW, Panorama, and Multi-Vsys configurations
"""
import re
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Tuple
from models.network_models import (
    NetworkDevice, Interface, SecurityZone, SecurityPolicy, NAT, VPN, Route, RoutingProtocol,
    DeviceType, InterfaceType, ProtocolType, NetworkTopology, VirtualRouter
)


class PaloAltoParser:
    """Enhanced parser for Palo Alto firewall and Panorama configurations"""

    def __init__(self):
        self.address_objects = {}
        self.address_groups = {}
        self.service_objects = {}
        self.service_groups = {}
        self.is_panorama = False
        self.managed_devices = []

    def parse(self, config_text: str) -> List[NetworkDevice]:
        """
        Parse Palo Alto configuration (auto-detect format)
        Returns a list of devices (single for NGFW, multiple for Panorama)
        """
        # Try to detect if it's XML or set-format
        if config_text.strip().startswith('<'):
            return self._parse_xml(config_text)
        else:
            return self._parse_set_format(config_text)

    def _parse_xml(self, config_text: str) -> List[NetworkDevice]:
        """Parse XML format configuration - supports NGFW and Panorama"""
        devices = []

        try:
            root = ET.fromstring(config_text)

            # Check if this is a Panorama configuration
            panorama_elem = root.find('.//panorama')
            managed_devices_elem = root.find('.//managed-devices')

            if panorama_elem is not None or managed_devices_elem is not None:
                self.is_panorama = True
                devices = self._parse_panorama_xml(root)
            else:
                # Single NGFW configuration
                device = self._parse_ngfw_xml(root)
                devices = [device]

        except ET.ParseError as e:
            print(f"Error parsing XML: {e}")

        return devices

    def _parse_panorama_xml(self, root: ET.Element) -> List[NetworkDevice]:
        """Parse Panorama configuration with multiple managed devices"""
        devices = []

        # Parse Panorama device itself
        panorama_device = NetworkDevice(
            hostname="Panorama",
            device_type=DeviceType.PALO_ALTO
        )

        # Get Panorama hostname
        hostname_elem = root.find('.//deviceconfig/system/hostname')
        if hostname_elem is not None and hostname_elem.text:
            panorama_device.hostname = hostname_elem.text

        # Parse managed devices
        managed_devices = root.find('.//managed-devices')
        if managed_devices is not None:
            for entry in managed_devices.findall('.//entry'):
                device = self._parse_managed_device(entry, root)
                if device:
                    devices.append(device)

        # Parse device groups (templates applied to managed devices)
        device_groups = root.find('.//device-group')
        if device_groups is not None:
            self._apply_device_group_configs(device_groups, devices)

        # Parse template stacks
        templates = root.find('.//template')
        if templates is not None:
            self._apply_template_configs(templates, devices)

        # Add Panorama device if it has configuration
        if panorama_device.hostname != "Panorama" or len(devices) == 0:
            devices.insert(0, panorama_device)

        return devices

    def _parse_managed_device(self, entry: ET.Element, root: ET.Element) -> Optional[NetworkDevice]:
        """Parse a single managed device from Panorama"""
        device_name = entry.get('name')
        if not device_name:
            return None

        device = NetworkDevice(
            hostname=device_name,
            device_type=DeviceType.PALO_ALTO
        )

        # Get device details
        hostname_elem = entry.find('.//hostname')
        if hostname_elem is not None and hostname_elem.text:
            device.hostname = hostname_elem.text

        serial_elem = entry.find('.//serial')
        if serial_elem is not None and serial_elem.text:
            device.serial_number = serial_elem.text

        model_elem = entry.find('.//model')
        if model_elem is not None and model_elem.text:
            device.model = model_elem.text

        ip_elem = entry.find('.//ip-address')
        if ip_elem is not None and ip_elem.text:
            device.management_ip = ip_elem.text

        # Check if device has multi-vsys enabled
        multi_vsys = entry.find('.//multi-vsys')
        if multi_vsys is not None and multi_vsys.text == 'yes':
            # Parse each vsys as a separate logical device
            vsys_devices = self._parse_multi_vsys(entry, device, root)
            return vsys_devices  # Return list of vsys devices

        return device

    def _parse_multi_vsys(self, device_entry: ET.Element, base_device: NetworkDevice,
                         root: ET.Element) -> List[NetworkDevice]:
        """Parse multi-vsys configuration into separate logical devices"""
        vsys_devices = []

        # Find vsys configurations in the device config
        vsys_configs = root.findall('.//vsys/entry')

        for vsys_entry in vsys_configs:
            vsys_name = vsys_entry.get('name', 'vsys1')

            # Create a new device for this vsys
            vsys_device = NetworkDevice(
                hostname=f"{base_device.hostname}-{vsys_name}",
                device_type=DeviceType.PALO_ALTO,
                management_ip=base_device.management_ip,
                serial_number=base_device.serial_number,
                model=base_device.model
            )

            # Parse vsys-specific configuration
            self._parse_vsys_config(vsys_entry, vsys_device, root)

            vsys_devices.append(vsys_device)

        # If no vsys configs found, return the base device
        if not vsys_devices:
            return [base_device]

        return vsys_devices

    def _parse_vsys_config(self, vsys_entry: ET.Element, device: NetworkDevice, root: ET.Element):
        """Parse configuration specific to a vsys"""
        vsys_name = vsys_entry.get('name', 'vsys1')

        # Parse zones for this vsys
        zones = vsys_entry.findall('.//zone/entry')
        for zone in zones:
            security_zone = self._parse_zone_xml(zone)
            if security_zone:
                device.security_zones.append(security_zone)

        # Parse security policies for this vsys
        policies = vsys_entry.findall('.//rulebase/security/rules/entry')
        for policy in policies:
            sec_policy = self._parse_security_policy_xml(policy)
            if sec_policy:
                device.security_policies.append(sec_policy)

        # Parse NAT policies for this vsys
        nat_rules = vsys_entry.findall('.//rulebase/nat/rules/entry')
        for nat_rule in nat_rules:
            nat = self._parse_nat_xml(nat_rule)
            if nat:
                device.nat_rules.append(nat)

    def _parse_ngfw_xml(self, root: ET.Element) -> NetworkDevice:
        """Parse single NGFW XML configuration"""
        device = NetworkDevice(
            hostname="Unknown",
            device_type=DeviceType.PALO_ALTO
        )

        # Hostname
        hostname_elem = root.find('.//deviceconfig/system/hostname')
        if hostname_elem is not None and hostname_elem.text:
            device.hostname = hostname_elem.text

        # Domain
        domain_elem = root.find('.//deviceconfig/system/domain')
        if domain_elem is not None and domain_elem.text:
            device.domain_name = domain_elem.text

        # Serial number
        serial_elem = root.find('.//deviceconfig/system/serial-number')
        if serial_elem is not None and serial_elem.text:
            device.serial_number = serial_elem.text

        # Check for multi-vsys
        multi_vsys_elem = root.find('.//deviceconfig/system/multi-vsys')
        if multi_vsys_elem is not None and multi_vsys_elem.text == 'yes':
            # Parse each vsys
            vsys_entries = root.findall('.//vsys/entry')
            if vsys_entries:
                # Create device for each vsys
                devices = []
                for vsys_entry in vsys_entries:
                    vsys_name = vsys_entry.get('name', 'vsys1')
                    vsys_device = NetworkDevice(
                        hostname=f"{device.hostname}-{vsys_name}",
                        device_type=DeviceType.PALO_ALTO,
                        management_ip=device.management_ip,
                        serial_number=device.serial_number
                    )
                    self._parse_vsys_config(vsys_entry, vsys_device, root)
                    devices.append(vsys_device)
                return devices[0] if len(devices) == 1 else devices

        # Parse shared/global objects
        self._parse_address_objects_xml(root)
        self._parse_service_objects_xml(root)

        # Parse network configuration
        self._parse_network_config(root, device)

        # Parse security configuration
        self._parse_security_config(root, device)

        return device

    def _parse_network_config(self, root: ET.Element, device: NetworkDevice):
        """Parse network configuration (interfaces, zones, routing)"""
        # Interfaces
        interfaces_elem = root.find('.//network/interface')
        if interfaces_elem is not None:
            for intf_type in interfaces_elem:
                for intf in intf_type:
                    interface = self._parse_interface_xml(intf, intf_type.tag)
                    if interface:
                        device.interfaces.append(interface)

        # Zones
        zones_elem = root.find('.//zone')
        if zones_elem is not None:
            for zone in zones_elem:
                security_zone = self._parse_zone_xml(zone)
                if security_zone:
                    device.security_zones.append(security_zone)

        # Virtual Routers - parse as VirtualRouter objects
        virtual_routers = root.findall('.//network/virtual-router/entry')
        vsys_name = device.vsys_name if hasattr(device, 'vsys_name') else None

        for vr_entry in virtual_routers:
            vr_name = vr_entry.get('name', 'default')
            vr = VirtualRouter(name=vr_name, vsys=vsys_name)

            # Get interfaces in this VR
            intf_members = vr_entry.findall('.//interface/member')
            for member in intf_members:
                if member.text:
                    vr.interfaces.append(member.text)
                    # Mark interface with VRF name
                    for intf in device.interfaces:
                        if intf.name == member.text:
                            intf.vrf = vr_name
                            intf.vsys = vsys_name

            # Parse routes for this VR
            routes = self._parse_routes_xml(vr_entry, vr_name)
            vr.routes.extend(routes)

            # Parse routing protocols for this VR
            protocols = self._parse_routing_protocols_xml(vr_entry, vr_name, vsys_name)
            vr.routing_protocols.extend(protocols)

            device.virtual_routers.append(vr)

    def _parse_security_config(self, root: ET.Element, device: NetworkDevice):
        """Parse security configuration (policies, NAT, VPN)"""
        # Security Policies
        policies_elem = root.find('.//rulebase/security/rules')
        if policies_elem is not None:
            for rule in policies_elem:
                policy = self._parse_security_policy_xml(rule)
                if policy:
                    device.security_policies.append(policy)

        # NAT Policies
        nat_elem = root.find('.//rulebase/nat/rules')
        if nat_elem is not None:
            for rule in nat_elem:
                nat = self._parse_nat_xml(rule)
                if nat:
                    device.nat_rules.append(nat)

        # VPN
        vpns = self._parse_vpn_xml(root)
        device.vpn_configs.extend(vpns)

    def _apply_device_group_configs(self, device_groups: ET.Element, devices: List[NetworkDevice]):
        """Apply device group configurations to managed devices"""
        for dg_entry in device_groups.findall('.//entry'):
            dg_name = dg_entry.get('name')

            # Find devices in this device group
            devices_elem = dg_entry.find('.//devices')
            if devices_elem is not None:
                for device_entry in devices_elem.findall('.//entry'):
                    device_name = device_entry.get('name')

                    # Find the corresponding device
                    for device in devices:
                        if device.hostname == device_name or device.serial_number == device_name:
                            # Apply device group config
                            self._apply_dg_config_to_device(dg_entry, device)

    def _apply_dg_config_to_device(self, dg_entry: ET.Element, device: NetworkDevice):
        """Apply specific device group configuration to a device"""
        # Parse security policies from device group
        policies = dg_entry.findall('.//pre-rulebase/security/rules/entry')
        for policy in policies:
            sec_policy = self._parse_security_policy_xml(policy)
            if sec_policy:
                device.security_policies.append(sec_policy)

        # Parse NAT rules from device group
        nat_rules = dg_entry.findall('.//pre-rulebase/nat/rules/entry')
        for nat_rule in nat_rules:
            nat = self._parse_nat_xml(nat_rule)
            if nat:
                device.nat_rules.append(nat)

    def _apply_template_configs(self, templates: ET.Element, devices: List[NetworkDevice]):
        """Apply template configurations to managed devices"""
        for template_entry in templates.findall('.//entry'):
            template_name = template_entry.get('name')

            # Parse network configuration from template
            # Templates typically contain interface, zone, and virtual router configs
            pass  # Template parsing can be added as needed

    def _parse_interface_xml(self, intf_elem, intf_type: str) -> Optional[Interface]:
        """Parse interface from XML"""
        name_attr = intf_elem.get('name')
        if not name_attr:
            return None

        full_name = f"{intf_type}.{name_attr}" if intf_type != 'ethernet' else name_attr

        interface = Interface(
            name=full_name,
            type=self._determine_interface_type(intf_type)
        )

        # Comment/description
        comment_elem = intf_elem.find('comment')
        if comment_elem is not None and comment_elem.text:
            interface.description = comment_elem.text

        # Layer 3 configuration
        layer3_elem = intf_elem.find('.//layer3')
        if layer3_elem is not None:
            ip_elem = layer3_elem.find('.//ip/entry')
            if ip_elem is not None:
                ip_name = ip_elem.get('name')
                if ip_name and '/' in ip_name:
                    parts = ip_name.split('/')
                    interface.ip_address = parts[0]
                    interface.subnet_mask = self._cidr_to_netmask(int(parts[1]))

        # Layer 2 configuration
        layer2_elem = intf_elem.find('.//layer2')
        if layer2_elem is not None:
            # Get VLAN info if present
            pass

        # VLAN
        vlan_elem = intf_elem.find('.//tag')
        if vlan_elem is not None and vlan_elem.text:
            try:
                interface.vlan = int(vlan_elem.text)
            except ValueError:
                pass

        return interface

    def _parse_zone_xml(self, zone_elem) -> Optional[SecurityZone]:
        """Parse security zone from XML"""
        name = zone_elem.get('name')
        if not name:
            return None

        zone = SecurityZone(name=name)

        # Interfaces
        network_elem = zone_elem.find('network')
        if network_elem is not None:
            for layer in network_elem:
                for member in layer:
                    if member.text:
                        zone.interfaces.append(member.text)

        return zone

    def _parse_routes_xml(self, vr_elem, vr_name: str = None) -> List[Route]:
        """Parse static routes from virtual router XML"""
        routes = []

        routing_table = vr_elem.find('.//routing-table/ip/static-route')
        if routing_table is not None:
            for route_entry in routing_table:
                name = route_entry.get('name')
                dest_elem = route_entry.find('destination')
                nexthop_elem = route_entry.find('nexthop')

                if dest_elem is not None and dest_elem.text:
                    destination = dest_elem.text
                    next_hop = None
                    interface = None

                    if nexthop_elem is not None:
                        ip_elem = nexthop_elem.find('ip-address')
                        if ip_elem is not None and ip_elem.text:
                            next_hop = ip_elem.text

                    # Parse destination
                    if '/' in destination:
                        dest_ip, cidr = destination.split('/')
                        netmask = self._cidr_to_netmask(int(cidr))
                    else:
                        dest_ip = destination
                        netmask = '255.255.255.255'

                    routes.append(Route(
                        destination=dest_ip,
                        mask=netmask,
                        next_hop=next_hop,
                        interface=interface,
                        protocol=ProtocolType.STATIC,
                        vrf=vr_name
                    ))

        return routes

    def _parse_routing_protocols_xml(self, vr_elem, vr_name: str = None, vsys_name: str = None) -> List[RoutingProtocol]:
        """Parse dynamic routing protocols from virtual router XML"""
        protocols = []

        # OSPF
        ospf_elem = vr_elem.find('.//protocol/ospf')
        if ospf_elem is not None and ospf_elem.find('enable') is not None:
            if ospf_elem.find('enable').text == 'yes':
                ospf = RoutingProtocol(protocol=ProtocolType.OSPF, vrf=vr_name, vsys=vsys_name)

                router_id = ospf_elem.find('router-id')
                if router_id is not None and router_id.text:
                    ospf.router_id = router_id.text

                # Areas
                areas = ospf_elem.findall('.//area/entry')
                for area in areas:
                    area_id = area.get('name')
                    if area_id:
                        ospf.areas.append(area_id)

                protocols.append(ospf)

        # BGP
        bgp_elem = vr_elem.find('.//protocol/bgp')
        if bgp_elem is not None and bgp_elem.find('enable') is not None:
            if bgp_elem.find('enable').text == 'yes':
                bgp = RoutingProtocol(protocol=ProtocolType.BGP, vrf=vr_name, vsys=vsys_name)

                router_id = bgp_elem.find('router-id')
                if router_id is not None and router_id.text:
                    bgp.router_id = router_id.text

                local_as = bgp_elem.find('local-as')
                if local_as is not None and local_as.text:
                    try:
                        bgp.autonomous_system = int(local_as.text)
                    except ValueError:
                        pass

                # Peer groups
                peer_groups = bgp_elem.findall('.//peer-group/entry')
                for pg in peer_groups:
                    peers = pg.findall('.//peer/entry')
                    for peer in peers:
                        peer_addr = peer.find('.//peer-address/ip')
                        if peer_addr is not None and peer_addr.text:
                            bgp.neighbors.append(peer_addr.text)

                            # Capture detailed peer information
                            peer_details = {'ip': peer_addr.text}

                            # Get remote AS
                            remote_as = peer.find('.//remote-as')
                            if remote_as is not None and remote_as.text:
                                peer_details['remote_as'] = remote_as.text

                            # Get peer name/description
                            peer_name = peer.get('name')
                            if peer_name:
                                peer_details['description'] = peer_name

                            bgp.bgp_peers.append(peer_details)

                protocols.append(bgp)

        return protocols

    def _parse_address_objects_xml(self, root):
        """Parse address objects from XML"""
        address_entries = root.findall('.//address/entry')
        for entry in address_entries:
            name = entry.get('name')
            if name:
                ip_elem = entry.find('ip-netmask')
                if ip_elem is not None and ip_elem.text:
                    self.address_objects[name] = ip_elem.text

                fqdn_elem = entry.find('fqdn')
                if fqdn_elem is not None and fqdn_elem.text:
                    self.address_objects[name] = fqdn_elem.text

        # Address groups
        group_entries = root.findall('.//address-group/entry')
        for entry in group_entries:
            name = entry.get('name')
            if name:
                members = []
                static = entry.find('static')
                if static is not None:
                    for member in static:
                        if member.text:
                            members.append(member.text)
                self.address_groups[name] = members

    def _parse_service_objects_xml(self, root):
        """Parse service objects from XML"""
        service_entries = root.findall('.//service/entry')
        for entry in service_entries:
            name = entry.get('name')
            if name:
                protocol_elem = entry.find('protocol')
                if protocol_elem is not None:
                    for proto in protocol_elem:
                        port_elem = proto.find('port')
                        if port_elem is not None and port_elem.text:
                            self.service_objects[name] = f"{proto.tag}/{port_elem.text}"

    def _parse_security_policy_xml(self, rule_elem) -> Optional[SecurityPolicy]:
        """Parse security policy from XML"""
        name = rule_elem.get('name')
        if not name:
            return None

        policy = SecurityPolicy(name=name)

        # Action
        action_elem = rule_elem.find('action')
        if action_elem is not None and action_elem.text:
            policy.action = action_elem.text

        # Source zone
        from_elem = rule_elem.find('from')
        if from_elem is not None:
            for member in from_elem:
                if member.text:
                    policy.source_zone = member.text
                    break

        # Destination zone
        to_elem = rule_elem.find('to')
        if to_elem is not None:
            for member in to_elem:
                if member.text:
                    policy.destination_zone = member.text
                    break

        # Source address
        source_elem = rule_elem.find('source')
        if source_elem is not None:
            for member in source_elem:
                if member.text:
                    policy.source_address.append(member.text)

        # Destination address
        dest_elem = rule_elem.find('destination')
        if dest_elem is not None:
            for member in dest_elem:
                if member.text:
                    policy.destination_address.append(member.text)

        # Service
        service_elem = rule_elem.find('service')
        if service_elem is not None:
            for member in service_elem:
                if member.text:
                    policy.service.append(member.text)

        # Application
        app_elem = rule_elem.find('application')
        if app_elem is not None:
            for member in app_elem:
                if member.text:
                    policy.application.append(member.text)

        return policy

    def _parse_nat_xml(self, rule_elem) -> Optional[NAT]:
        """Parse NAT rule from XML"""
        name = rule_elem.get('name')

        nat = NAT(type='dynamic')

        # Source translation
        source_trans = rule_elem.find('.//source-translation')
        if source_trans is not None:
            dynamic_ip = source_trans.find('dynamic-ip-and-port')
            if dynamic_ip is not None:
                translated = dynamic_ip.find('translated-address')
                if translated is not None:
                    for member in translated:
                        if member.text:
                            nat.translated_source = member.text
                            break

            static_ip = source_trans.find('static-ip')
            if static_ip is not None:
                nat.type = 'static'
                translated = static_ip.find('translated-address')
                if translated is not None and translated.text:
                    nat.translated_source = translated.text

        # Destination translation
        dest_trans = rule_elem.find('.//destination-translation')
        if dest_trans is not None:
            trans_addr = dest_trans.find('translated-address')
            if trans_addr is not None and trans_addr.text:
                nat.translated_destination = trans_addr.text

        return nat

    def _parse_vpn_xml(self, root) -> List[VPN]:
        """Parse VPN configurations from XML"""
        vpns = []

        # IKE Gateways
        ike_gateways = root.findall('.//ike/gateway/entry')
        for gw in ike_gateways:
            name = gw.get('name')
            if not name:
                continue

            vpn = VPN(name=name, type='ipsec')

            # Peer address
            peer_elem = gw.find('.//peer-address/ip')
            if peer_elem is not None and peer_elem.text:
                vpn.peer = peer_elem.text

            # Local address
            local_elem = gw.find('.//local-address/ip')
            if local_elem is not None and local_elem.text:
                vpn.local_network = [local_elem.text]

            # Authentication
            auth_elem = gw.find('.//authentication/pre-shared-key')
            if auth_elem is not None:
                vpn.authentication = 'pre-shared-key'

            vpns.append(vpn)

        # IPSec Tunnels
        ipsec_tunnels = root.findall('.//ipsec/entry')
        for tunnel in ipsec_tunnels:
            name = tunnel.get('name')
            if not name:
                continue

            # Try to match with IKE gateway
            gw_elem = tunnel.find('.//ike-gateway')
            if gw_elem is not None and gw_elem.text:
                # Find corresponding VPN
                for vpn in vpns:
                    if vpn.name == gw_elem.text:
                        tunnel_intf = tunnel.find('.//tunnel-interface')
                        if tunnel_intf is not None and tunnel_intf.text:
                            vpn.tunnel_interface = tunnel_intf.text

        return vpns

    def _parse_set_format(self, config_text: str) -> List[NetworkDevice]:
        """Parse set-format configuration"""
        device = NetworkDevice(
            hostname="Unknown",
            device_type=DeviceType.PALO_ALTO
        )

        lines = config_text.split('\n')

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Hostname
            if 'set deviceconfig system hostname' in line:
                device.hostname = line.split()[-1]

            # Domain
            elif 'set deviceconfig system domain' in line:
                device.domain_name = line.split()[-1]

            # Interface
            elif 'set network interface' in line:
                interface = self._parse_interface_set(line)
                if interface:
                    existing = device.get_interface(interface.name)
                    if existing:
                        if interface.ip_address:
                            existing.ip_address = interface.ip_address
                        if interface.description:
                            existing.description = interface.description
                    else:
                        device.interfaces.append(interface)

            # Zone
            elif 'set zone' in line:
                zone = self._parse_zone_set(line)
                if zone:
                    existing = device.get_zone(zone.name)
                    if existing:
                        existing.interfaces.extend(zone.interfaces)
                    else:
                        device.security_zones.append(zone)

            # Route
            elif 'set network virtual-router' in line and 'routing-table ip static-route' in line:
                route = self._parse_route_set(line)
                if route:
                    device.routes.append(route)

        return [device]

    def _parse_interface_set(self, line: str) -> Optional[Interface]:
        """Parse interface from set-format"""
        match = re.search(r'interface (\S+) (\S+)', line)
        if not match:
            return None

        intf_type = match.group(1)
        intf_name = match.group(2)

        interface = Interface(
            name=intf_name,
            type=self._determine_interface_type(intf_type)
        )

        # IP address
        if 'layer3 ip' in line:
            parts = line.split()
            for i, part in enumerate(parts):
                if part == 'ip' and i + 1 < len(parts):
                    ip_cidr = parts[i + 1]
                    if '/' in ip_cidr:
                        ip, cidr = ip_cidr.split('/')
                        interface.ip_address = ip
                        interface.subnet_mask = self._cidr_to_netmask(int(cidr))

        # Comment
        if 'comment' in line:
            match = re.search(r'comment ["\']?([^"\']+)["\']?', line)
            if match:
                interface.description = match.group(1)

        return interface

    def _parse_zone_set(self, line: str) -> Optional[SecurityZone]:
        """Parse security zone from set-format"""
        match = re.search(r'set zone (\S+)', line)
        if not match:
            return None

        zone_name = match.group(1)
        zone = SecurityZone(name=zone_name)

        if 'network layer3' in line or 'network layer2' in line:
            parts = line.split()
            if parts[-1]:
                zone.interfaces.append(parts[-1])

        return zone

    def _parse_route_set(self, line: str) -> Optional[Route]:
        """Parse static route from set-format"""
        match = re.search(r'destination (\S+)', line)
        if not match:
            return None

        destination = match.group(1)
        if '/' in destination:
            dest_ip, cidr = destination.split('/')
            netmask = self._cidr_to_netmask(int(cidr))
        else:
            dest_ip = destination
            netmask = '255.255.255.255'

        next_hop = None
        match = re.search(r'nexthop ip-address (\S+)', line)
        if match:
            next_hop = match.group(1)

        return Route(
            destination=dest_ip,
            mask=netmask,
            next_hop=next_hop,
            protocol=ProtocolType.STATIC
        )

    def _determine_interface_type(self, intf_type: str) -> InterfaceType:
        """Determine interface type"""
        intf_lower = intf_type.lower()
        if 'ethernet' in intf_lower:
            return InterfaceType.PHYSICAL
        elif 'vlan' in intf_lower:
            return InterfaceType.VLAN
        elif 'loopback' in intf_lower:
            return InterfaceType.LOOPBACK
        elif 'tunnel' in intf_lower:
            return InterfaceType.TUNNEL
        else:
            return InterfaceType.PHYSICAL

    def _cidr_to_netmask(self, cidr: int) -> str:
        """Convert CIDR to netmask"""
        mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
