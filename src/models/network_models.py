"""
Network Models for representing parsed configuration data
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum


class DeviceType(Enum):
    """Types of network devices"""
    CISCO_NEXUS = "cisco_nexus"
    CISCO_CATALYST = "cisco_catalyst"
    CISCO_ASA = "cisco_asa"
    PALO_ALTO = "palo_alto"


class InterfaceType(Enum):
    """Types of interfaces"""
    PHYSICAL = "physical"
    VLAN = "vlan"
    LOOPBACK = "loopback"
    MANAGEMENT = "management"
    PORT_CHANNEL = "port_channel"
    TUNNEL = "tunnel"
    SVI = "svi"


class ProtocolType(Enum):
    """Routing protocols"""
    STATIC = "static"
    OSPF = "ospf"
    EIGRP = "eigrp"
    BGP = "bgp"
    RIP = "rip"
    ISIS = "isis"


@dataclass
class Interface:
    """Network interface"""
    name: str
    type: InterfaceType
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    description: Optional[str] = None
    vlan: Optional[int] = None
    enabled: bool = True
    speed: Optional[str] = None
    duplex: Optional[str] = None
    channel_group: Optional[int] = None
    trunk_vlans: List[int] = field(default_factory=list)
    access_vlan: Optional[int] = None
    native_vlan: Optional[int] = None
    mac_address: Optional[str] = None
    mtu: Optional[int] = None
    vrf: Optional[str] = None  # VRF/Virtual Router name
    vsys: Optional[str] = None  # Virtual System (Palo Alto)

    def __hash__(self):
        return hash(self.name)


@dataclass
class VLAN:
    """VLAN configuration"""
    vlan_id: int
    name: Optional[str] = None
    description: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    vrf: Optional[str] = None  # VRF this VLAN belongs to

    def __hash__(self):
        return hash(self.vlan_id)


@dataclass
class Route:
    """Static or dynamic route"""
    destination: str
    mask: str
    next_hop: Optional[str] = None
    interface: Optional[str] = None
    protocol: ProtocolType = ProtocolType.STATIC
    administrative_distance: Optional[int] = None
    metric: Optional[int] = None
    vrf: Optional[str] = None  # VRF/Virtual Router name

    def __hash__(self):
        return hash((self.destination, self.mask, self.next_hop, self.interface))


@dataclass
class RoutingProtocol:
    """Routing protocol configuration"""
    protocol: ProtocolType
    process_id: Optional[str] = None
    router_id: Optional[str] = None
    networks: List[Dict[str, str]] = field(default_factory=list)
    neighbors: List[str] = field(default_factory=list)
    areas: List[str] = field(default_factory=list)
    autonomous_system: Optional[int] = None
    redistributed_protocols: List[str] = field(default_factory=list)
    vrf: Optional[str] = None  # VRF/Virtual Router name
    vsys: Optional[str] = None  # Virtual System (Palo Alto)
    bgp_peers: List[Dict[str, str]] = field(default_factory=list)  # BGP peer details: [{ip, remote_as, description}]


@dataclass
class VirtualRouter:
    """Virtual Router / VRF configuration"""
    name: str
    interfaces: List[str] = field(default_factory=list)
    routes: List[Route] = field(default_factory=list)
    routing_protocols: List[RoutingProtocol] = field(default_factory=list)
    route_distinguisher: Optional[str] = None
    vsys: Optional[str] = None  # Which VSYS this VR belongs to (Palo Alto)

    def __hash__(self):
        return hash(self.name)


@dataclass
class SecurityZone:
    """Security zone (for firewalls)"""
    name: str
    interfaces: List[str] = field(default_factory=list)
    security_level: Optional[int] = None

    def __hash__(self):
        return hash(self.name)


@dataclass
class SecurityPolicy:
    """Security policy/ACL"""
    name: str
    source_zone: Optional[str] = None
    destination_zone: Optional[str] = None
    source_address: List[str] = field(default_factory=list)
    destination_address: List[str] = field(default_factory=list)
    service: List[str] = field(default_factory=list)
    action: str = "permit"
    application: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class NAT:
    """NAT configuration"""
    type: str  # static, dynamic, pat
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    original_source: Optional[str] = None
    translated_source: Optional[str] = None
    original_destination: Optional[str] = None
    translated_destination: Optional[str] = None


@dataclass
class VPN:
    """VPN configuration"""
    name: str
    type: str  # ipsec, ssl
    peer: Optional[str] = None
    local_network: List[str] = field(default_factory=list)
    remote_network: List[str] = field(default_factory=list)
    encryption: Optional[str] = None
    authentication: Optional[str] = None
    tunnel_interface: Optional[str] = None


@dataclass
class NetworkDevice:
    """Complete network device representation"""
    hostname: str
    device_type: DeviceType
    management_ip: Optional[str] = None
    domain_name: Optional[str] = None

    # Physical and logical components
    interfaces: List[Interface] = field(default_factory=list)
    vlans: List[VLAN] = field(default_factory=list)
    virtual_routers: List[VirtualRouter] = field(default_factory=list)

    # Routing (global or if no VRF/VR configured)
    routes: List[Route] = field(default_factory=list)
    routing_protocols: List[RoutingProtocol] = field(default_factory=list)

    # Security (for firewalls)
    security_zones: List[SecurityZone] = field(default_factory=list)
    security_policies: List[SecurityPolicy] = field(default_factory=list)
    nat_rules: List[NAT] = field(default_factory=list)
    vpn_configs: List[VPN] = field(default_factory=list)

    # Additional metadata
    software_version: Optional[str] = None
    serial_number: Optional[str] = None
    model: Optional[str] = None
    vsys_name: Optional[str] = None  # Virtual System name (Palo Alto)

    def get_interface(self, name: str) -> Optional[Interface]:
        """Get interface by name"""
        for interface in self.interfaces:
            if interface.name == name:
                return interface
        return None

    def get_vlan(self, vlan_id: int) -> Optional[VLAN]:
        """Get VLAN by ID"""
        for vlan in self.vlans:
            if vlan.vlan_id == vlan_id:
                return vlan
        return None

    def get_zone(self, name: str) -> Optional[SecurityZone]:
        """Get security zone by name"""
        for zone in self.security_zones:
            if zone.name == name:
                return zone
        return None

    def get_virtual_router(self, name: str) -> Optional['VirtualRouter']:
        """Get virtual router by name"""
        for vr in self.virtual_routers:
            if vr.name == name:
                return vr
        return None

    def add_virtual_router(self, vr: 'VirtualRouter'):
        """Add a virtual router"""
        self.virtual_routers.append(vr)


@dataclass
class NetworkTopology:
    """Complete network topology"""
    devices: List[NetworkDevice] = field(default_factory=list)
    connections: List[Dict[str, str]] = field(default_factory=list)

    def add_device(self, device: NetworkDevice):
        """Add device to topology"""
        self.devices.append(device)

    def add_connection(self, device1: str, interface1: str, device2: str, interface2: str):
        """Add connection between devices"""
        self.connections.append({
            "device1": device1,
            "interface1": interface1,
            "device2": device2,
            "interface2": interface2
        })

    def get_device(self, hostname: str) -> Optional[NetworkDevice]:
        """Get device by hostname"""
        for device in self.devices:
            if device.hostname == hostname:
                return device
        return None
