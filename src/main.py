#!/usr/bin/env python3
"""
Network Configuration Parser and Diagram Generator
Main CLI interface
"""
import argparse
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers.cisco_nexus_parser import CiscoNexusParser
from parsers.cisco_catalyst_parser import CiscoCatalystParser
from parsers.cisco_asa_parser import CiscoASAParser
from parsers.palo_alto_parser import PaloAltoParser

from models.network_models import NetworkTopology

from generators.network_connection_diagram import NetworkConnectionDiagram
from generators.logical_diagram import LogicalDiagram
from generators.topology_diagram import TopologyDiagram
from generators.routing_diagram import RoutingDiagram

from analyzers.connection_discovery import ConnectionDiscovery


class NetworkDiagramGenerator:
    """Main orchestrator for parsing configs and generating diagrams"""

    def __init__(self):
        self.topology = NetworkTopology()
        self.parsers = {
            'cisco_nexus': CiscoNexusParser(),
            'cisco_catalyst': CiscoCatalystParser(),
            'cisco_asa': CiscoASAParser(),
            'palo_alto': PaloAltoParser()
        }

    def parse_config(self, config_file: str, device_type: str):
        """Parse a configuration file"""
        print(f"Parsing {config_file} as {device_type}...")

        # Read configuration file
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_text = f.read()
        except Exception as e:
            print(f"Error reading file {config_file}: {e}")
            return False

        # Parse configuration
        try:
            parser = self.parsers.get(device_type)
            if not parser:
                print(f"Unknown device type: {device_type}")
                return False

            # Parse returns either a single device or list of devices (Palo Alto Panorama/multi-vsys)
            result = parser.parse(config_text)

            # Handle both single device and list of devices
            if isinstance(result, list):
                devices = result
            else:
                devices = [result]

            # Add all devices to topology
            for device in devices:
                self.topology.add_device(device)
                print(f"  ✓ Parsed device: {device.hostname}")
                print(f"    - Interfaces: {len(device.interfaces)}")
                print(f"    - VLANs: {len(device.vlans)}")
                print(f"    - Routes: {len(device.routes)}")
                print(f"    - Routing Protocols: {len(device.routing_protocols)}")
                if device.security_zones:
                    print(f"    - Security Zones: {len(device.security_zones)}")
                if device.security_policies:
                    print(f"    - Security Policies: {len(device.security_policies)}")

            return True

        except Exception as e:
            print(f"Error parsing {config_file}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def parse_directory(self, directory: str, device_type: str = None):
        """Parse all configuration files in a directory"""
        path = Path(directory)

        if not path.is_dir():
            print(f"Error: {directory} is not a directory")
            return

        # Find all .txt, .cfg, .conf, .xml files
        config_files = []
        for ext in ['*.txt', '*.cfg', '*.conf', '*.xml']:
            config_files.extend(path.glob(ext))

        if not config_files:
            print(f"No configuration files found in {directory}")
            return

        print(f"Found {len(config_files)} configuration file(s)")

        for config_file in config_files:
            # Auto-detect device type if not specified
            detected_type = device_type
            if not detected_type:
                detected_type = self._detect_device_type(str(config_file))

            if detected_type:
                self.parse_config(str(config_file), detected_type)
            else:
                print(f"Skipping {config_file.name} - could not detect device type")

    def _detect_device_type(self, config_file: str) -> str:
        """Auto-detect device type from configuration content"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                content = f.read(1000)  # Read first 1000 chars

                # Check for XML (Palo Alto)
                if content.strip().startswith('<'):
                    return 'palo_alto'

                # Check for Cisco ASA
                if 'ASA Version' in content or 'security-level' in content or 'nameif' in content:
                    return 'cisco_asa'

                # Check for Cisco Nexus
                if 'Cisco Nexus' in content or 'feature' in content[:200]:
                    return 'cisco_nexus'

                # Default to Catalyst for Cisco configs
                if 'hostname' in content or 'interface' in content:
                    return 'cisco_catalyst'

        except Exception as e:
            print(f"Error detecting device type for {config_file}: {e}")

        return None

    def generate_diagrams(self, output_dir: str = 'output', diagram_types: list = None):
        """Generate diagrams"""
        if not self.topology.devices:
            print("No devices parsed. Nothing to generate.")
            return

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Default to all diagram types
        if not diagram_types:
            diagram_types = ['connection', 'logical', 'topology', 'routing']

        print(f"\nGenerating diagrams for {len(self.topology.devices)} device(s)...")

        # Run connection discovery
        print("\n  Running connection discovery...")
        discovery = ConnectionDiscovery(self.topology)
        discovery.discover_all()
        print(discovery.get_connection_summary())

        # Print detailed connections
        discovery.print_discovered_connections()

        # Generate Network Connection Diagram
        if 'connection' in diagram_types:
            print("  Generating Network Connection Diagram...")
            try:
                conn_diagram = NetworkConnectionDiagram()
                output_file = os.path.join(output_dir, 'network_connection.drawio')
                conn_diagram.generate(self.topology, output_file)
                print(f"    ✓ Saved to {output_file}")
            except Exception as e:
                print(f"    ✗ Error: {e}")

        # Generate Logical Diagram
        if 'logical' in diagram_types:
            print("  Generating Logical Diagram...")
            try:
                logical_diagram = LogicalDiagram()
                output_file = os.path.join(output_dir, 'logical_diagram.drawio')
                logical_diagram.generate(self.topology, output_file)
                print(f"    ✓ Saved to {output_file}")
            except Exception as e:
                print(f"    ✗ Error: {e}")

        # Generate Topology Diagram
        if 'topology' in diagram_types:
            print("  Generating Topology Diagram...")
            try:
                topo_diagram = TopologyDiagram()
                output_file = os.path.join(output_dir, 'topology_diagram.drawio')
                topo_diagram.generate(self.topology, output_file)
                print(f"    ✓ Saved to {output_file}")
            except Exception as e:
                print(f"    ✗ Error: {e}")

        # Generate Routing Diagram
        if 'routing' in diagram_types:
            print("  Generating Routing Diagram...")
            try:
                routing_diagram = RoutingDiagram()
                output_file = os.path.join(output_dir, 'routing_diagram.drawio')
                routing_diagram.generate(self.topology, output_file)
                print(f"    ✓ Saved to {output_file}")
            except Exception as e:
                print(f"    ✗ Error: {e}")

        print(f"\n✓ Diagrams generated successfully in {output_dir}/")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Parse network device configurations and generate Draw.io diagrams',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse a single configuration file
  python main.py -f config.txt -t cisco_nexus

  # Parse all configs in a directory (auto-detect device types)
  python main.py -d configs/

  # Parse directory and specify device type
  python main.py -d configs/ -t cisco_catalyst

  # Generate specific diagram types
  python main.py -d configs/ --diagrams topology routing

Supported device types:
  - cisco_nexus     : Cisco Nexus Switch
  - cisco_catalyst  : Cisco Catalyst Switch
  - cisco_asa       : Cisco ASA Firewall
  - palo_alto       : Palo Alto Firewall/Panorama

Generated diagrams:
  - connection      : Network/Connection Drawing
  - logical         : Logical Drawing (VLANs, Zones)
  - topology        : Topology Drawing
  - routing         : Routing Drawing
        """
    )

    parser.add_argument('-f', '--file', help='Configuration file to parse')
    parser.add_argument('-d', '--directory', help='Directory containing configuration files')
    parser.add_argument('-t', '--type', choices=['cisco_nexus', 'cisco_catalyst', 'cisco_asa', 'palo_alto'],
                       help='Device type (auto-detected if not specified)')
    parser.add_argument('-o', '--output', default='output', help='Output directory for diagrams (default: output)')
    parser.add_argument('--diagrams', nargs='+', choices=['connection', 'logical', 'topology', 'routing'],
                       help='Specific diagrams to generate (default: all)')

    args = parser.parse_args()

    # Validate input
    if not args.file and not args.directory:
        parser.print_help()
        print("\nError: You must specify either -f/--file or -d/--directory")
        sys.exit(1)

    # Create generator
    generator = NetworkDiagramGenerator()

    # Parse configurations
    if args.file:
        if not args.type:
            print("Error: -t/--type is required when using -f/--file")
            sys.exit(1)
        generator.parse_config(args.file, args.type)
    elif args.directory:
        generator.parse_directory(args.directory, args.type)

    # Generate diagrams
    generator.generate_diagrams(args.output, args.diagrams)


if __name__ == '__main__':
    main()
