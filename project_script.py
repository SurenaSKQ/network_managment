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
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    
    # Create hosts with IP addresses
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    
    # Create links
    net.addLink(s1, s2)
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

# SECTION: Testing utilities

def test_connectivity(net):
    """Test routing between hosts"""
    info("*** Testing basic connectivity\n")
    h1, h2 = net.get('h1'), net.get('h2')
    
    # Ping test with 5 packets
    result = h1.cmd('ping -c 5', h2.IP())
    info(result)
    
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
    """Simulate UDP flood attack from attacker host to target IP"""
    attacker_host = net.get(attacker)
    # Launch persistent UDP flood in background
    attacker_host.cmd(f'hping3 --flood --udp -p 80 {target_ip} &')
    info(f"*** DDoS ATTACK STARTED: {attacker} flooding {target_ip}\n")

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
            f'{FLOW_API}/{switch_id}',
            json=block_flow,
            auth=(ONOS_USER, ONOS_PASS),
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 201:
            info(f'*** MITIGATION: Blocked {attacker_ip} on {switch}\n')
        else:
            info(f'*** MITIGATION FAILED: {response.text}\n')

def verify_attack_impact(net, src, dst, duration=10):
    """Test connectivity during attack"""
    info("*** MEASURING ATTACK IMPACT (this will take 10 sec)\n")
    server = net.get(dst)
    client = net.get(src)
    
    # Start iPerf server on target
    server.cmd('iperf -s -u -i 1 > server.log &')
    time.sleep(1)
    
    # Run iPerf client through attack
    client.cmd(f'iperf -c {server.IP()} -u -b 100M -t {duration}')
    
    # Show server results
    info("*** ATTACK TRAFFIC RESULTS:\n")
    info(server.cmd('cat server.log') + '\n')

def main():
    setLogLevel('info')
    net = create_network()

    try:
        net.start()
        info("*** Network started. Waiting for controller connection...\n")
        time.sleep(10)  # Allow controller-switch handshake
        check_controller_connection()

        install_arp_flows(SWITCH1_DPID)
        install_arp_flows(SWITCH2_DPID)

        # Install demonstration flows
        install_flows(SWITCH1_DPID, '10.0.0.1/32', '10.0.0.2/32', 2)  # h1->h2 via s1-s2
        install_flows(SWITCH2_DPID, '10.0.0.2/32', '10.0.0.1/32', 1)  # h2->h1 via s2-s1
        
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
            ping_test(net, 'h2', TARGET)  # Should recover
            verify_attack_impact(net, 'h2', TARGET)  # Traffic should normalize
        finally:
            # Cleanup attack processes
            net.get(ATTACKER).cmd('killall hping3')
            # Start CLI for manual exploration
            info("\n*** Starting CLI for interactive commands\n")
            CLI(net)
    finally:
        net.stop()

if __name__ == '__main__':
    main()
