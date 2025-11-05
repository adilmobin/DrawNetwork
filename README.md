# Network Configuration Parser and Draw.io Diagram Generator

A comprehensive Python tool that parses network device configurations and automatically generates professional network diagrams in Draw.io format.

## Features

### Supported Devices
- **Cisco Nexus Switch** - Data center switching platform
- **Cisco Catalyst Switch** - Enterprise switching platform
- **Cisco ASA Firewall** - Adaptive Security Appliance
- **Palo Alto Firewall/Panorama** - Next-generation firewall (supports both XML and set-format configs)

### Generated Diagrams

The tool automatically generates **four types of professional network diagrams**:

1. **Network/Connection Drawing** - Shows physical and logical connections between devices with interface details
2. **Logical Drawing** - Displays VLANs, security zones, and logical network segmentation
3. **Topology Drawing** - Hierarchical network topology (WAN, Core, Distribution, Access layers)
4. **Routing Drawing** - Routing protocols, routing domains (OSPF areas, BGP AS), and route propagation

### Parsed Elements

- Network interfaces (physical, VLAN, loopback, management)
- IP addressing and subnets
- VLANs and trunk configurations
- Static routes
- Dynamic routing protocols (OSPF, BGP, EIGRP, RIP, IS-IS)
- Security zones (for firewalls)
- Security policies and ACLs
- NAT rules (static and dynamic)
- VPN configurations (IPSec, SSL)

## Installation

### Requirements
- Python 3.7 or higher
- No external dependencies (uses only Python standard library)

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/DrawNetwork.git
cd DrawNetwork

# No additional installation needed - uses only standard library
```

## Usage

### Basic Usage

#### Parse a single configuration file
```bash
cd src
python main.py -f /path/to/config.txt -t cisco_nexus
```

#### Parse all configs in a directory (auto-detect device types)
```bash
python main.py -d /path/to/configs/
```

#### Parse directory with specific device type
```bash
python main.py -d /path/to/configs/ -t cisco_catalyst
```

#### Generate specific diagram types only
```bash
python main.py -d /path/to/configs/ --diagrams topology routing
```

#### Specify output directory
```bash
python main.py -d /path/to/configs/ -o /path/to/output/
```

### Command-Line Options

```
Options:
  -h, --help            Show help message
  -f FILE, --file FILE  Configuration file to parse
  -d DIR, --directory DIR
                        Directory containing configuration files
  -t TYPE, --type TYPE  Device type: cisco_nexus, cisco_catalyst, cisco_asa, palo_alto
  -o DIR, --output DIR  Output directory for diagrams (default: output)
  --diagrams TYPES      Specific diagrams to generate: connection, logical, topology, routing
```

## Examples

### Example 1: Parse sample configurations
```bash
cd src
python main.py -d ../examples/sample_configs/
```

### Example 2: Parse Cisco Nexus switch only
```bash
python main.py -f ../examples/sample_configs/cisco_nexus.txt -t cisco_nexus
```

### Example 3: Generate only topology and routing diagrams
```bash
python main.py -d ../examples/sample_configs/ --diagrams topology routing -o ../output/
```

## Output

The tool generates `.drawio` files that can be opened with:
- [Draw.io Desktop](https://github.com/jgraph/drawio-desktop/releases)
- [Draw.io Web](https://app.diagrams.net/)
- [VS Code Draw.io Extension](https://marketplace.visualstudio.com/items?itemName=hediet.vscode-drawio)

### Output Files
- `network_connection.drawio` - Network connection diagram
- `logical_diagram.drawio` - Logical network diagram
- `topology_diagram.drawio` - Network topology diagram
- `routing_diagram.drawio` - Routing protocol diagram

## Project Structure

```
DrawNetwork/
├── src/
│   ├── main.py                          # Main CLI interface
│   ├── parsers/
│   │   ├── cisco_nexus_parser.py        # Cisco Nexus parser
│   │   ├── cisco_catalyst_parser.py     # Cisco Catalyst parser
│   │   ├── cisco_asa_parser.py          # Cisco ASA parser
│   │   └── palo_alto_parser.py          # Palo Alto parser
│   ├── models/
│   │   └── network_models.py            # Data models
│   └── generators/
│       ├── drawio_generator.py          # Base Draw.io generator
│       ├── network_connection_diagram.py # Connection diagram
│       ├── logical_diagram.py           # Logical diagram
│       ├── topology_diagram.py          # Topology diagram
│       └── routing_diagram.py           # Routing diagram
├── examples/
│   └── sample_configs/                  # Example configurations
│       ├── cisco_nexus.txt
│       ├── cisco_catalyst.txt
│       ├── cisco_asa.txt
│       └── palo_alto_set.txt
├── requirements.txt
└── README.md
```

## Diagram Types Explained

### 1. Network/Connection Diagram
Shows the physical connections between devices with:
- Device icons (switches, routers, firewalls)
- Connection lines with interface names
- IP addresses on interfaces
- Interface descriptions

**Use case**: Understanding how devices are physically connected

### 2. Logical Diagram
Displays logical network segmentation:
- VLANs as containers with member devices
- Security zones (for firewalls)
- Security policies between zones
- VLAN membership and trunking

**Use case**: Understanding logical network boundaries and security policies

### 3. Topology Diagram
Hierarchical view of network topology:
- Layered layout (WAN, Firewall, Core, Distribution, Access)
- Device classification by role
- Subnet-based connection inference
- Internet/WAN cloud for edge devices

**Use case**: Understanding network hierarchy and design

### 4. Routing Diagram
Routing protocol visualization:
- Routing domains (OSPF areas, BGP AS, EIGRP AS)
- OSPF adjacencies
- BGP peering relationships
- Static routes
- Route summary by protocol

**Use case**: Understanding routing design and protocol relationships

## Supported Configuration Formats

### Cisco Nexus/Catalyst
```
hostname SWITCH-01
interface Ethernet1/1
  ip address 10.0.0.1/24
  no shutdown
vlan 10
  name DATA
router ospf 1
  router-id 1.1.1.1
  network 10.0.0.0/24 area 0
```

### Cisco ASA
```
hostname ASA-FW-01
interface GigabitEthernet0/0
  nameif outside
  security-level 0
  ip address 203.0.113.10 255.255.255.248
object network INSIDE-NET
  nat (inside,outside) dynamic interface
access-list outside_in extended permit tcp any host 10.0.0.5 eq 443
```

### Palo Alto (Set Format)
```
set deviceconfig system hostname PA-FW-01
set network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/24
set zone trust network layer3 ethernet1/2
set rulebase security rules allow-out action allow
```

### Palo Alto (XML Format)
XML configurations exported from Palo Alto devices are also supported.

## Auto-Detection

The tool can automatically detect device types based on configuration content:
- XML format → Palo Alto
- Contains "security-level" or "nameif" → Cisco ASA
- Contains "feature" statements → Cisco Nexus
- Standard Cisco IOS syntax → Cisco Catalyst

## Limitations

- Connection inference is based on IP subnets; physical connections may require manual verification
- Complex routing scenarios (route-maps, policy routing) are simplified
- Firewall policy details are summarized for readability
- VPN configurations show basic tunnel information

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is provided as-is for educational and professional use.

## Support

For issues, questions, or feature requests, please open an issue on the GitHub repository.

## Acknowledgments

- Uses Draw.io (diagrams.net) XML format
- Cisco network stencils from Draw.io library
- Inspired by network documentation best practices
