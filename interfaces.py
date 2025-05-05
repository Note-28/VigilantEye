import subprocess
import psutil
import socket
from scapy.all import get_if_list, get_if_hwaddr
from utils import logger

INTERFACE_MAP = {}  # Map friendly names to Scapy interface IDs

def get_netsh_interfaces():
    """Get interface information using netsh command"""
    try:
        # Get interfaces from netsh
        result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                              capture_output=True, text=True, check=True)
        
        interfaces = []
        lines = result.stdout.split('\n')
        
        # Skip header lines
        for line in lines[3:]:
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 4:
                admin_state = parts[0]
                state = parts[1]
                interface_type = parts[2]
                name = ' '.join(parts[3:])
                
                # Include all interfaces, not just enabled ones
                interfaces.append({
                    'name': name,
                    'state': state,
                    'type': interface_type,
                    'admin_state': admin_state
                })
        
        # Also get interfaces from ipconfig for additional information
        result = subprocess.run(['ipconfig', '/all'], 
                              capture_output=True, text=True, check=True)
        
        # Parse ipconfig output to get additional interface information
        current_adapter = None
        ipconfig_info = {}
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            if not line.startswith(' '):
                # This is an adapter name
                if 'adapter' in line.lower():
                    current_adapter = line.split('adapter ')[-1].strip(':')
                    ipconfig_info[current_adapter] = {}
            elif current_adapter and ':' in line:
                # This is an adapter property
                key, value = line.split(':', 1)
                ipconfig_info[current_adapter][key.strip()] = value.strip()
        
        logger.debug(f"IPConfig info: {ipconfig_info}")
        return interfaces, ipconfig_info
        
    except Exception as e:
        logger.error(f"Error getting netsh interfaces: {e}")
        return [], {}

def get_windows_interfaces():
    """Get a list of available network interfaces with friendly names"""
    global INTERFACE_MAP
    interfaces = []
    
    try:
        logger.debug("Starting interface detection...")
        
        # Get Scapy interfaces
        scapy_interfaces = get_if_list()
        logger.debug(f"Scapy interfaces: {scapy_interfaces}")
        
        # Get netsh and ipconfig interfaces
        netsh_interfaces, ipconfig_info = get_netsh_interfaces()
        logger.debug(f"Netsh interfaces: {netsh_interfaces}")
        
        # Get network interfaces from psutil
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        # Process each netsh interface
        for netsh_iface in netsh_interfaces:
            try:
                iface_name = netsh_iface['name']
                
                # Get MAC and IP addresses from psutil
                mac = "00:00:00:00:00:00"
                ip_addresses = []
                
                # Try to get information from ipconfig
                for adapter_name, info in ipconfig_info.items():
                    if iface_name.lower() in adapter_name.lower() or adapter_name.lower() in iface_name.lower():
                        if 'Physical Address' in info:
                            mac = info['Physical Address']
                        if 'IPv4 Address' in info:
                            ip = info['IPv4 Address']
                            if '(' in ip:
                                ip = ip.split('(')[0].strip()
                            ip_addresses.append(ip)
                
                # Try to get information from psutil
                if iface_name in net_if_addrs:
                    addrs = net_if_addrs[iface_name]
                    for addr in addrs:
                        if addr.family == psutil.AF_LINK and not mac:
                            mac = addr.address
                        elif addr.family == socket.AF_INET and addr.address not in ip_addresses:
                            ip_addresses.append(addr.address)
                
                # Find corresponding Scapy interface
                scapy_iface = None
                for scapy_if in scapy_interfaces:
                    # Try to match by name or MAC
                    if (iface_name.lower() in scapy_if.lower() or
                        scapy_if.lower() in iface_name.lower() or
                        (mac != "00:00:00:00:00:00" and mac.lower() in scapy_if.lower())):
                        scapy_iface = scapy_if
                        break
                
                if not scapy_iface:
                    # If no match found, try to find any unused interface
                    for scapy_if in scapy_interfaces:
                        if not any(si.get('scapy_iface') == scapy_if for si in interfaces):
                            scapy_iface = scapy_if
                            break
                
                if not scapy_iface:
                    continue
                
                # Determine interface type
                iface_type = "Other"
                if "wi-fi" in iface_name.lower():
                    iface_type = "Wi-Fi"
                elif "ethernet" in iface_name.lower() or "local area connection" in iface_name.lower():
                    iface_type = "Ethernet"
                elif "vethernet" in iface_name.lower() or "hyper-v" in iface_name.lower() or "wsl" in iface_name.lower():
                    iface_type = "Virtual"
                
                # Create display name
                if ip_addresses:
                    display_name = f"{iface_name} ({ip_addresses[0]})"
                else:
                    display_name = f"{iface_name} ({mac})"
                
                # Add to interface map
                INTERFACE_MAP[display_name] = scapy_iface
                
                interface_info = {
                    "id": scapy_iface,
                    "name": display_name,
                    "mac": mac,
                    "ip_addresses": ip_addresses,
                    "original_name": iface_name,
                    "type": iface_type,
                    "state": netsh_iface['state'],
                    "admin_state": netsh_iface['admin_state'],
                    "scapy_iface": scapy_iface
                }
                
                interfaces.append(interface_info)
                logger.debug(f"Added interface: {interface_info}")
                
            except Exception as e:
                logger.debug(f"Error processing interface {iface_name}: {e}")
                continue
        
        # Sort interfaces by state and type
        interfaces.sort(key=lambda x: (
            0 if x["admin_state"].lower() == "enabled" else 1,  # Enabled interfaces first
            0 if x["state"].lower() == "connected" else 1,      # Connected interfaces next
            0 if x["type"] == "Wi-Fi" else                      # Then by type
            1 if x["type"] == "Ethernet" else
            2 if x["type"] == "Virtual" else
            3
        ))
        
        logger.info(f"Found {len(interfaces)} interfaces: {[i['name'] for i in interfaces]}")
        return interfaces
        
    except Exception as e:
        logger.error(f"Error in get_windows_interfaces: {e}")
        return []

def validate_interface(iface):
    """Validate if the interface exists"""
    try:
        interfaces = get_if_list()
        logger.debug(f"Available interfaces: {interfaces}")
        logger.debug(f"Checking interface: {iface}")
        if iface in interfaces:
            return True
        # Try to find a partial match
        for available_iface in interfaces:
            if iface in available_iface or available_iface in iface:
                logger.debug(f"Found partial match: {available_iface}")
                return True
        logger.error(f"Interface {iface} not found in available interfaces")
        return False
    except Exception as e:
        logger.error(f"Error validating interface: {e}")
        return False