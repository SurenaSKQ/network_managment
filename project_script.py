#!/usr/bin/env python3
# AUTHORS
# Surena Karimpour Ghannadi
# Mehrshad Najafi 
# Amirmohammad Hassannejhad
# This file is provided under 0BSD license.

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import requests
import time
import re

# SECTION: Constants

# ONOS credentials and API endpoint
ONOS_IP = '127.0.0.1'
ONOS_USER = 'onos'
ONOS_PASS = 'rocks'
FLOW_API = f'http://{ONOS_IP}:8181/onos/v1/flows'
# Switch IDs
SWITCH1_DPID = 'of:0000000000000001'
SWITCH2_DPID = 'of:0000000000000002'


# SECTION: Fundamental functions

def create_network():
    """Create SDN topology with OpenFlow switches and hosts"""
    net = Mininet(controller=None)
    
    # Connect to ONOS controller
    net.addController('onos', 
                      controller=RemoteController,
                      ip=ONOS_IP, 
                      port=6653,
                      protocols='OpenFlow13')
    
    # Create switches
    s1 = net.addSwitch('s1', dpid="0000000000000001",protocols='OpenFlow13')
    s2 = net.addSwitch('s2', dpid="0000000000000002", protocols='OpenFlow13')
    
    # Create hosts with IP addresses
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')

    # Create LIMITED bandwidth link with queue management
    net.addLink(s1, s2, 
                bw=10, 
                delay='1ms', 
                max_queue_size=10,  # Small buffer for rapid congestion
                use_htb=True)  # Hierarchical Token Bucket for accuracy
    
    # Create links
    net.addLink(h1, s1)
    net.addLink(h2, s2)
    net.addLink(h3, s2)
    
    return net

def install_flows(switch_id, src_ip, dst_ip, out_port):
    """Install proactive flow rules via ONOS REST API"""

    url = f'{FLOW_API}/{switch_id}'

    flow = {
        "priority": 40000,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": switch_id,
        "treatment": {
            "instructions": [
                {"type": "OUTPUT", "port": out_port}
            ]
        },
        "selector": {
            "criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0800"},  # IPv4
                {"type": "IPV4_SRC", "ip": src_ip},
                {"type": "IPV4_DST", "ip": dst_ip}
            ]
        }
    }
    
    response = requests.post(
        url,
        json=flow,
        auth=(ONOS_USER, ONOS_PASS),
        headers={'Content-Type': 'application/json'}
    )
    
    if response.status_code == 201:
        info(f'Flow installed on {switch_id} for {src_ip}->{dst_ip}\n')
    else:
        info(f'Error installing flow: {response.text}\n')

def install_arp_flows(device_id):
    """Install ARP handling flow on specific device"""
    url = f"{FLOW_API}/{device_id}"
    
    arp_flow = {
        "priority": 41000,
        "timeout": 0,
        "isPermanent": True,
        "treatment": {"instructions": [{"type": "OUTPUT", "port": "CONTROLLER"}]},
        "selector": {"criteria": [{"type": "ETH_TYPE", "ethType": "0x0806"}]}  # ARP
    }
    
    response = requests.post(
        url,
        json=arp_flow,
        auth=(ONOS_USER, ONOS_PASS),
        headers={'Content-Type': 'application/json'}
    )
    
    if response.status_code in (200, 201):
        info(f'ARP flow installed on {device_id}\n')
    else:
        info(f'Failed to install ARP flow on {device_id}: {response.text}\n')

def install_table_miss_flow(device_id):
    url = f"{FLOW_API}/{device_id}"
    flow = {
        "priority": 0,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": device_id,
        "treatment": {"instructions": [{"type": "OUTPUT", "port": "CONTROLLER"}]},
        "selector": {}
    }
    response = requests.post(
        url,
        json=flow,
        auth=(ONOS_USER, ONOS_PASS),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code in (200, 201):
        info(f'Table-miss flow installed on {device_id}\n')
    else:
        info(f'Failed to install table-miss flow: {response.text}\n')

def install_arp_proxy_flows(switch_id, ip_prefix):
    """Install ARP proxy flows to handle L2 resolution without controller"""
    arp_proxy_flow = {
        "priority": 42000,
        "timeout": 0,
        "isPermanent": True,
        "treatment": {
            "instructions": [
                {
                    "type": "L2MODIFICATION",
                    "subtype": "ETH_DST",
                    "mac": "00:00:00:00:00:FF"  # Proxy MAC
                },
                {"type": "OUTPUT", "port": "CONTROLLER"}
            ]
        },
        "selector": {
            "criteria": [
                {"type": "ETH_TYPE", "ethType": "0x0806"},  # ARP
                {"type": "IPV4_DST", "ip": f"{ip_prefix}"}  # Target subnet
            ]
        }
    }
    response = requests.post(
        f"{FLOW_API}/{switch_id}",
        json=arp_proxy_flow,
        auth=(ONOS_USER, ONOS_PASS),
        headers={'Content-Type': 'application/json'}
    )
    info(f'ARP proxy installed on {switch_id} for {ip_prefix}\n')

def preconfigure_arp(net):
    """Preconfigure static ARP entries to bypass resolution"""
    info("*** Preconfiguring ARP tables\n")
    hosts = [net.get('h1'), net.get('h2'), net.get('h3')]
    ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3']
    macs = [h.MAC() for h in hosts]
    
    for i, host in enumerate(hosts):
        for j, ip in enumerate(ips):
            if i != j:  # Skip self
                host.cmd(f'arp -s {ip} {macs[j]}')

def get_host_port(switch, host_name):
    """Dynamically find port number for host connection"""
    for intf in switch.intfList():
        link = intf.link
        if link:
            node1, node2 = link.intf1.node, link.intf2.node
            if host_name in [node1.name, node2.name]:
                return intf.node.ports[intf]
    return None

# SECTION: Testing utilities

def test_connectivity(net):
    """Test routing between hosts"""
    info("*** Testing basic connectivity\n")
    net.pingAll()
    # Show installed flows
    info("\n*** Displaying active flows in ONOS\n")
    flows = requests.get(FLOW_API, auth=(ONOS_USER, ONOS_PASS)).json()
    for flow in flows['flows']:
        info(f"Switch: {flow['deviceId']}, "
             f"Selector: {flow['selector']['criteria']}, "
             f"Action: {flow['treatment']['instructions']}\n")

def ping_test(net, src, dst, count=3):
    """Perform ping test between hosts"""
    src_host = net.get(src)
    dst_ip = net.get(dst).IP()
    result = src_host.cmd(f'ping -c {count} {dst_ip}')
    info(f"*** PING TEST {src} -> {dst}:\n{result}\n")

def check_controller_connection():
    """Verify ONOS is reachable and switches connected"""
    devices_url = f'http://{ONOS_IP}:8181/onos/v1/devices'
    try:
        response = requests.get(devices_url, auth=(ONOS_USER, ONOS_PASS))
        info(f"*** Controller status: {response.status_code}\n")
        if response.status_code == 200:
            devices = response.json()['devices']
            for d in devices:
                info(f"Connected: {d['id']} ({d['available']})\n")
    except Exception as e:
        info(f"Controller connection failed: {str(e)}\n")


# SECTION: DDOS utilities

def launch_ddos_attack(net, attacker, target_ip):
    """Generate high-intensity traffic using kernel-level tools"""
    attacker_host = net.get(attacker)
    
    # Kernel-level UDP flood (bypass Python limitations)
    attacker_host.cmd(f'sudo nping --rate 1000000 --udp -p 80 -c 0 {target_ip} > /dev/null 2>&1 &')
    
    # TCP SYN flood with raw sockets
    attacker_host.cmd(f'sudo hping3 --faster -S -p 80 {target_ip} > /dev/null 2>&1 &')
    
    # HTTP flood with high concurrency
    attacker_host.cmd(f'siege -b -c 500 -t 300s http://{target_ip} > /dev/null 2>&1 &')
    
    info(f"*** CARRIER-GRADE DDoS STARTED: {attacker} ➔ {target_ip}\n")

def mitigate_ddos(switches, attacker_ip):
    """Install blocking flows against attacker IP on all switches"""
    for switch in switches:
        block_flow = {
            "priority": 50000,  # Higher than normal flows
            "timeout": 0,
            "isPermanent": True,
            "deviceId": switch,
            "treatment": {"instructions": []},  # Empty treatment = DROP
            "selector": {
                "criteria": [
                    {"type": "ETH_TYPE", "ethType": "0x0800"},  # IPv4
                    {"type": "IPV4_SRC", "ip": attacker_ip}
                ]
            }
        }
        response = requests.post(
            f'{FLOW_API}/{switch}',
            json=block_flow,
            auth=(ONOS_USER, ONOS_PASS),
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 201:
            info(f'*** MITIGATION: Blocked {attacker_ip} on {switch}\n')
        else:
            info(f'*** MITIGATION FAILED: {response.text}\n')

def verify_attack_impact(net, src, dst, duration=15):
    """Measure network degradation during attack"""
    server = net.get(dst)
    client = net.get(src)
    s1 = net.get('s1')  # Get switch object

    # Start traffic monitor on BOTTLENECK LINK (s1-eth0)
    bottleneck_intf = 's1-eth0'  # First interface = s1-s2 link
    s1.cmd(f'tcpdump -i {bottleneck_intf} -w bottleneck.pcap &')

    # Start iPerf server
    server.cmd('iperf -s -u -i 1 > server.log &')
    time.sleep(1)

    # Run bandwidth test through attack
    client.cmd(f'iperf -c {server.IP()} -u -b 100M -t {duration}')

    # Collect metrics
    info("⦿ ATTACK IMPACT REPORT:\n")
    info(server.cmd('cat server.log') + '\n')

    # Get queue statistics - FIXED INTERFACE NAME
    queue_stats = s1.cmd(f'tc -s qdisc show dev {bottleneck_intf}')
    match = re.search(r'dropped (\d+)', queue_stats)
    packet_loss = match.group(1) if match else '0'
    info(f"⦿ SWITCH QUEUE DROPS: {packet_loss} packets\n")

    # Get ping statistics
    ping_result = client.cmd(f'ping -c {duration} -i 0.2 {server.IP()} | grep -e "loss" -e "avg"')
    info(f"⦿ PING STATISTICS:\n{ping_result}\n")

    # Cleanup
    s1.cmd('killall tcpdump')
    server.cmd('killall iperf')

def main():
    setLogLevel('info')
    net = create_network()

    try:
        net.start()

        info("*** Network started. Waiting for controller connection...\n")
        time.sleep(10)  # Allow controller-switch handshake
        check_controller_connection()

        requests.post(
            f'http://{ONOS_IP}:8181/onos/v1/applications/org.onosproject.fwd/deactivate',
            auth=(ONOS_USER, ONOS_PASS)
        )
        info("*** DISABLED REACTIVE FORWARDING APP\n")
        
        # Install critical flows 
        install_table_miss_flow(SWITCH1_DPID)
        install_table_miss_flow(SWITCH2_DPID)
        install_arp_flows(SWITCH1_DPID)  # Original ARP to controller
        install_arp_flows(SWITCH2_DPID)
        install_arp_proxy_flows(SWITCH1_DPID, "10.0.0.0/24")  # New proxy flows
        install_arp_proxy_flows(SWITCH2_DPID, "10.0.0.0/24")
        
        # Preconfigure host ARP tables
        preconfigure_arp(net)

        # Get switch objects and dynamically detect ports
        s1 = net.get('s1')
        s2 = net.get('s2')
        s1_s2_port = get_host_port(s1, 's2')  # Port on s1 connected to s2
        s1_h1_port = get_host_port(s1, 'h1')  # Port on s1 connected to h1
        s2_s1_port = get_host_port(s2, 's1')  # Port on s2 connected to s1
        s2_h2_port = get_host_port(s2, 'h2')  # Port on s2 connected to h2
        s2_h3_port = get_host_port(s2, 'h3')  # Port on s2 connected to h3

        # Print detected ports for debugging
        info(f"*** Detected Port Mapping:\n"
             f"s1-s2: port {s1_s2_port}\n"
             f"s1-h1: port {s1_h1_port}\n"
             f"s2-s1: port {s2_s1_port}\n"
             f"s2-h2: port {s2_h2_port}\n"
             f"s2-h3: port {s2_h3_port}\n")

        # Install demonstration flows using DYNAMIC PORTS
        # s1 Flows
        install_flows(SWITCH1_DPID, '10.0.0.1/32', '10.0.0.2/32', s1_s2_port)  # h1->h2 via s1-s2
        install_flows(SWITCH1_DPID, '10.0.0.1/32', '10.0.0.3/32', s1_s2_port)  # h1->h3 via s1-s2
        install_flows(SWITCH1_DPID, '10.0.0.2/32', '10.0.0.1/32', s1_h1_port)  # h2->h1 via s1-h1
        install_flows(SWITCH1_DPID, '10.0.0.3/32', '10.0.0.1/32', s1_h1_port)  # h3->h1 via s1-h1

        # s2 Flows
        install_flows(SWITCH2_DPID, '10.0.0.2/32', '10.0.0.1/32', s2_s1_port)  # h2->h1 via s2-s1
        install_flows(SWITCH2_DPID, '10.0.0.3/32', '10.0.0.1/32', s2_s1_port)  # h3->h1 via s2-s1
        install_flows(SWITCH2_DPID, '10.0.0.3/32', '10.0.0.2/32', s2_h2_port)  # h3->h2 via s2-h2
        install_flows(SWITCH2_DPID, '10.0.0.1/32', '10.0.0.2/32', s2_h2_port)  # h1->h2 via s2-h2
        install_flows(SWITCH2_DPID, '10.0.0.1/32', '10.0.0.3/32', s2_h3_port)  # h1->h3 via s2-h3
        install_flows(SWITCH2_DPID, '10.0.0.2/32', '10.0.0.3/32', s2_h3_port)  # h2->h3 via s2-h3

        # After installing flows but before ping tests
        info("*** ARP Table Diagnostics:\n")
        for host in ['h1', 'h2', 'h3']:
            arp_table = net.get(host).cmd('arp -n')
            info(f"{host} ARP Cache:\n{arp_table}\n")
       
        info("*** Validating Port Assignments:\n")
        for switch in [s1, s2]:
            for intf in switch.intfList():
                if not intf.link:
                    continue
                info(f"{switch.name} {intf.name} -> {intf.link.intf2.node.name}\n")
                
        # Test routing
        ping_test(net, 'h1', 'h2')
        ping_test(net, 'h1', 'h3')

        time.sleep(12) # Wait for controller

        test_connectivity(net)

        ATTACKER = 'h3'
        TARGET = 'h1'
        ATTACKER_IP = '10.0.0.3/32'
        
        try:
            # 1. Start DDoS attack
            launch_ddos_attack(net, ATTACKER, net.get(TARGET).IP())
            
            # 2. Verify attack impact
            verify_attack_impact(net, 'h2', TARGET)  # Test h2->h1 during attack
            
            # 3. Mitigate attack
            mitigate_ddos([SWITCH2_DPID], ATTACKER_IP)  # Block attacker IP
            time.sleep(3)  # Allow flow installation
           
            # 4. Verify mitigation
            info("*** VERIFYING MITIGATION EFFECTIVENESS\n")
            ping_test(net, ATTACKER, TARGET) # Should be blocked
            ping_test(net, 'h2', TARGET)  # Should recover
            verify_attack_impact(net, 'h2', TARGET)  # Traffic should normalize
        finally:
            # Cleanup attack processes
            net.get(ATTACKER).cmd('killall hping3 curl > /dev/null 2>&1')
            # Start CLI for manual exploration
            info("\n*** Starting CLI for interactive commands\n")
            CLI(net)
    finally:
        net.stop()

if __name__ == '__main__':
    main()
