"""
Draw.io XML Generator
Generates Draw.io compatible XML diagrams with proper network stencils
"""
import xml.etree.ElementTree as ET
from xml.dom import minidom
from typing import List, Dict, Tuple, Optional
from models.network_models import NetworkDevice, DeviceType, Interface


class DrawIOGenerator:
    """Base Draw.io diagram generator"""

    def __init__(self):
        self.next_id = 2  # Start at 2 since 0 and 1 are reserved for default cells
        self.cell_map = {}  # Maps object names to cell IDs

    def create_diagram(self, name: str = "Network Diagram") -> Tuple[ET.Element, ET.Element]:
        """Create base diagram structure"""
        mxfile = ET.Element('mxfile', {
            'host': 'app.diagrams.net',
            'modified': '2024-01-01T00:00:00.000Z',
            'agent': 'NetworkConfigParser',
            'version': '21.1.0',
            'type': 'device'
        })

        diagram = ET.SubElement(mxfile, 'diagram', {
            'id': 'diagram1',
            'name': name
        })

        mxGraphModel = ET.SubElement(diagram, 'mxGraphModel', {
            'dx': '1422',
            'dy': '794',
            'grid': '1',
            'gridSize': '10',
            'guides': '1',
            'tooltips': '1',
            'connect': '1',
            'arrows': '1',
            'fold': '1',
            'page': '1',
            'pageScale': '1',
            'pageWidth': '1169',
            'pageHeight': '827',
            'math': '0',
            'shadow': '0'
        })

        root = ET.SubElement(mxGraphModel, 'root')

        # Add default cells (required by Draw.io)
        ET.SubElement(root, 'mxCell', {'id': '0'})
        ET.SubElement(root, 'mxCell', {'id': '1', 'parent': '0'})

        return mxfile, root

    def get_next_id(self) -> str:
        """Get next unique ID"""
        id_str = str(self.next_id)
        self.next_id += 1
        return id_str

    def add_device(self, root: ET.Element, device: NetworkDevice, x: int, y: int,
                   width: int = 120, height: int = 120) -> str:
        """Add a network device to the diagram"""
        cell_id = self.get_next_id()
        self.cell_map[device.hostname] = cell_id

        # Determine device style based on type
        style = self._get_device_style(device.device_type)

        # Create label with device info
        label = self._create_device_label(device)

        cell = ET.SubElement(root, 'mxCell', {
            'id': cell_id,
            'value': label,
            'style': style,
            'vertex': '1',
            'parent': '1'
        })

        ET.SubElement(cell, 'mxGeometry', {
            'x': str(x),
            'y': str(y),
            'width': str(width),
            'height': str(height),
            'as': 'geometry'
        })

        return cell_id

    def add_switch(self, root: ET.Element, name: str, x: int, y: int,
                   label_text: Optional[str] = None) -> str:
        """Add a switch icon"""
        cell_id = self.get_next_id()
        self.cell_map[name] = cell_id

        style = (
            'sketch=0;points=[[0.015,0.015,0],[0.985,0.015,0],[0.985,0.985,0],'
            '[0.015,0.985,0],[0.25,0,0],[0.5,0,0],[0.75,0,0],[1,0.25,0],[1,0.5,0],'
            '[1,0.75,0],[0.75,1,0],[0.5,1,0],[0.25,1,0],[0,0.75,0],[0,0.5,0],[0,0.25,0]];'
            'verticalLabelPosition=bottom;html=1;verticalAlign=top;aspect=fixed;align=center;'
            'pointerEvents=1;shape=mxgraph.cisco19.rect;prIcon=l2_switch;'
            'fillColor=#005073;strokeColor=none;'
        )

        label = label_text if label_text else name

        cell = ET.SubElement(root, 'mxCell', {
            'id': cell_id,
            'value': label,
            'style': style,
            'vertex': '1',
            'parent': '1'
        })

        ET.SubElement(cell, 'mxGeometry', {
            'x': str(x),
            'y': str(y),
            'width': '100',
            'height': '100',
            'as': 'geometry'
        })

        return cell_id

    def add_router(self, root: ET.Element, name: str, x: int, y: int,
                   label_text: Optional[str] = None) -> str:
        """Add a router icon"""
        cell_id = self.get_next_id()
        self.cell_map[name] = cell_id

        style = (
            'sketch=0;points=[[0.5,0,0],[1,0.5,0],[0.5,1,0],[0,0.5,0],[0.145,0.145,0],'
            '[0.8555,0.145,0],[0.855,0.8555,0],[0.145,0.855,0]];'
            'verticalLabelPosition=bottom;html=1;verticalAlign=top;aspect=fixed;align=center;'
            'pointerEvents=1;shape=mxgraph.cisco19.rect;prIcon=router;'
            'fillColor=#005073;strokeColor=none;'
        )

        label = label_text if label_text else name

        cell = ET.SubElement(root, 'mxCell', {
            'id': cell_id,
            'value': label,
            'style': style,
            'vertex': '1',
            'parent': '1'
        })

        ET.SubElement(cell, 'mxGeometry', {
            'x': str(x),
            'y': str(y),
            'width': '100',
            'height': '100',
            'as': 'geometry'
        })

        return cell_id

    def add_firewall(self, root: ET.Element, name: str, x: int, y: int,
                     label_text: Optional[str] = None) -> str:
        """Add a firewall icon"""
        cell_id = self.get_next_id()
        self.cell_map[name] = cell_id

        style = (
            'sketch=0;points=[[0.5,0,0],[1,0.5,0],[0.5,1,0],[0,0.5,0],[0.145,0.145,0],'
            '[0.8555,0.145,0],[0.855,0.8555,0],[0.145,0.855,0]];'
            'verticalLabelPosition=bottom;html=1;verticalAlign=top;aspect=fixed;align=center;'
            'pointerEvents=1;shape=mxgraph.cisco19.rect;prIcon=firewall;'
            'fillColor=#a20025;strokeColor=#6F0000;'
        )

        label = label_text if label_text else name

        cell = ET.SubElement(root, 'mxCell', {
            'id': cell_id,
            'value': label,
            'style': style,
            'vertex': '1',
            'parent': '1'
        })

        ET.SubElement(cell, 'mxGeometry', {
            'x': str(x),
            'y': str(y),
            'width': '100',
            'height': '100',
            'as': 'geometry'
        })

        return cell_id

    def add_cloud(self, root: ET.Element, name: str, x: int, y: int,
                  label_text: Optional[str] = None) -> str:
        """Add a cloud icon (for Internet/WAN)"""
        cell_id = self.get_next_id()
        self.cell_map[name] = cell_id

        style = (
            'ellipse;shape=cloud;whiteSpace=wrap;html=1;'
            'fillColor=#dae8fc;strokeColor=#6c8ebf;'
        )

        label = label_text if label_text else name

        cell = ET.SubElement(root, 'mxCell', {
            'id': cell_id,
            'value': label,
            'style': style,
            'vertex': '1',
            'parent': '1'
        })

        ET.SubElement(cell, 'mxGeometry', {
            'x': str(x),
            'y': str(y),
            'width': '120',
            'height': '80',
            'as': 'geometry'
        })

        return cell_id

    def add_network_segment(self, root: ET.Element, name: str, x: int, y: int,
                           width: int = 300, height: int = 200) -> str:
        """Add a network segment/zone container"""
        cell_id = self.get_next_id()
        self.cell_map[name] = cell_id

        style = (
            'rounded=1;whiteSpace=wrap;html=1;fillColor=#f5f5f5;'
            'strokeColor=#666666;fontColor=#333333;dashed=1;dashPattern=8 8;'
        )

        cell = ET.SubElement(root, 'mxCell', {
            'id': cell_id,
            'value': name,
            'style': style,
            'vertex': '1',
            'parent': '1'
        })

        ET.SubElement(cell, 'mxGeometry', {
            'x': str(x),
            'y': str(y),
            'width': str(width),
            'height': str(height),
            'as': 'geometry'
        })

        return cell_id

    def add_connection(self, root: ET.Element, source_id: str, target_id: str,
                      label: str = '', style: Optional[str] = None) -> str:
        """Add a connection between two devices"""
        cell_id = self.get_next_id()

        if style is None:
            style = (
                'endArrow=none;html=1;rounded=0;'
                'strokeColor=#000000;strokeWidth=2;'
            )

        cell = ET.SubElement(root, 'mxCell', {
            'id': cell_id,
            'value': label,
            'style': style,
            'edge': '1',
            'parent': '1',
            'source': source_id,
            'target': target_id
        })

        ET.SubElement(cell, 'mxGeometry', {
            'relative': '1',
            'as': 'geometry'
        })

        return cell_id

    def add_text_label(self, root: ET.Element, text: str, x: int, y: int,
                      width: int = 200, height: int = 30) -> str:
        """Add a text label"""
        cell_id = self.get_next_id()

        style = (
            'text;html=1;strokeColor=none;fillColor=none;align=left;'
            'verticalAlign=middle;whiteSpace=wrap;rounded=0;'
        )

        cell = ET.SubElement(root, 'mxCell', {
            'id': cell_id,
            'value': text,
            'style': style,
            'vertex': '1',
            'parent': '1'
        })

        ET.SubElement(cell, 'mxGeometry', {
            'x': str(x),
            'y': str(y),
            'width': str(width),
            'height': str(height),
            'as': 'geometry'
        })

        return cell_id

    def add_interface_label(self, root: ET.Element, interface: Interface,
                           x: int, y: int) -> str:
        """Add an interface label with IP address"""
        text = f"{interface.name}"
        if interface.ip_address:
            text += f"\n{interface.ip_address}"
        if interface.description:
            text += f"\n({interface.description})"

        return self.add_text_label(root, text, x, y, width=150, height=60)

    def _get_device_style(self, device_type: DeviceType) -> str:
        """Get appropriate style for device type"""
        if device_type == DeviceType.CISCO_NEXUS or device_type == DeviceType.CISCO_CATALYST:
            return (
                'sketch=0;points=[[0.015,0.015,0],[0.985,0.015,0],[0.985,0.985,0],'
                '[0.015,0.985,0],[0.25,0,0],[0.5,0,0],[0.75,0,0],[1,0.25,0],[1,0.5,0],'
                '[1,0.75,0],[0.75,1,0],[0.5,1,0],[0.25,1,0],[0,0.75,0],[0,0.5,0],[0,0.25,0]];'
                'verticalLabelPosition=bottom;html=1;verticalAlign=top;aspect=fixed;align=center;'
                'pointerEvents=1;shape=mxgraph.cisco19.rect;prIcon=l2_switch;'
                'fillColor=#005073;strokeColor=none;'
            )
        elif device_type == DeviceType.CISCO_ASA or device_type == DeviceType.PALO_ALTO:
            return (
                'sketch=0;points=[[0.5,0,0],[1,0.5,0],[0.5,1,0],[0,0.5,0],[0.145,0.145,0],'
                '[0.8555,0.145,0],[0.855,0.8555,0],[0.145,0.855,0]];'
                'verticalLabelPosition=bottom;html=1;verticalAlign=top;aspect=fixed;align=center;'
                'pointerEvents=1;shape=mxgraph.cisco19.rect;prIcon=firewall;'
                'fillColor=#a20025;strokeColor=#6F0000;'
            )
        else:
            return 'rounded=1;whiteSpace=wrap;html=1;'

    def _create_device_label(self, device: NetworkDevice) -> str:
        """Create label text for device"""
        label = f"<b>{device.hostname}</b>"
        if device.management_ip:
            label += f"<br/>{device.management_ip}"
        if device.model:
            label += f"<br/><i>{device.model}</i>"
        return label

    def save_diagram(self, mxfile: ET.Element, filename: str):
        """Save diagram to file"""
        # Convert to pretty XML
        xml_str = ET.tostring(mxfile, encoding='unicode')
        dom = minidom.parseString(xml_str)
        pretty_xml = dom.toprettyxml(indent='  ')

        # Remove extra blank lines
        lines = [line for line in pretty_xml.split('\n') if line.strip()]
        pretty_xml = '\n'.join(lines)

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(pretty_xml)

    def calculate_grid_position(self, index: int, columns: int = 4,
                               spacing_x: int = 200, spacing_y: int = 200,
                               offset_x: int = 100, offset_y: int = 100) -> Tuple[int, int]:
        """Calculate grid position for device placement"""
        row = index // columns
        col = index % columns
        x = offset_x + col * spacing_x
        y = offset_y + row * spacing_y
        return x, y
