#!/usr/bin/python3
import requests
import urllib.parse
from requests.auth import HTTPBasicAuth

# ONOS Controller Configuration
ONOS_IP = "127.0.0.1"
ONOS_PORT = "8181"
ONOS_USER = "onos"
ONOS_PASS = "rocks"
BASE_URL = f"http://{ONOS_IP}:{ONOS_PORT}/onos/v1"
AUTH = HTTPBasicAuth(ONOS_USER, ONOS_PASS)
HEADERS = {'Accept': 'application/json'}

def delete_flows():
    """Delete all flows by first getting all flows, then deleting individually"""
    # Get all flows in the system
    flows_url = f"{BASE_URL}/flows"
    try:
        response = requests.get(flows_url, auth=AUTH, headers=HEADERS)
        if response.status_code != 200:
            print(f"Error getting flows: {response.status_code} - {response.text}")
            return

        flows = response.json().get("flows", [])
        print(f"Found {len(flows)} flows to delete")

        # Delete each flow individually
        for flow in flows:
            device_id = flow['deviceId']
            flow_id = flow['id']

            # URL-encode identifiers
            device_enc = urllib.parse.quote(device_id, safe='')
            flow_enc = urllib.parse.quote(flow_id, safe='')

            # Build delete URL
            delete_url = f"{BASE_URL}/flows/{device_enc}/{flow_enc}"
            del_response = requests.delete(delete_url, auth=AUTH, headers=HEADERS)

            if del_response.status_code in [200, 204]:
                print(f"Deleted flow {flow_id} on device {device_id}")
            else:
                print(f"Error deleting flow {flow_id} on device {device_id}: "
                      f"{del_response.status_code} - {del_response.text}")
    except Exception as e:
        print(f"Flow deletion error: {str(e)}")

def delete_hosts():
    """Delete all hosts individually using hostId from the host objects"""
    hosts_url = f"{BASE_URL}/hosts"
    try:
        response = requests.get(hosts_url, auth=AUTH, headers=HEADERS)
        if response.status_code != 200:
            print(f"Error getting hosts: {response.status_code} - {response.text}")
            return

        hosts = response.json().get("hosts", [])
        for host in hosts:
            host_id = host["id"]
            # Properly encode the hostId for URL
            host_enc = urllib.parse.quote(host_id, safe='')
            
            delete_url = f"{BASE_URL}/hosts/{host_enc}"
            del_response = requests.delete(delete_url, auth=AUTH, headers=HEADERS)
            
            if del_response.status_code in [200, 204]:
                print(f"Deleted host: {host_id}")
            else:
                print(f"Error deleting host {host_id}: {del_response.status_code} - {del_response.text}")
    except Exception as e:
        print(f"Host deletion error: {str(e)}")

def delete_devices():
    """Delete all devices individually"""
    devices_url = f"{BASE_URL}/devices"
    try:
        response = requests.get(devices_url, auth=AUTH, headers=HEADERS)
        if response.status_code != 200:
            print(f"Error getting devices: {response.status_code} - {response.text}")
            return

        devices = response.json().get("devices", [])
        for device in devices:
            device_id = device["id"]
            device_enc = urllib.parse.quote(device_id, safe='')
            delete_url = f"{BASE_URL}/devices/{device_enc}"
            del_response = requests.delete(delete_url, auth=AUTH, headers=HEADERS)
            if del_response.status_code in [200, 204]:
                print(f"Deleted device: {device_id}")
            else:
                print(f"Error deleting device {device_id}: {del_response.status_code} - {del_response.text}")
    except Exception as e:
        print(f"Device deletion error: {str(e)}")

if __name__ == "__main__":
    print("Starting ONOS cleanup...")
    delete_flows()
    delete_hosts()
    delete_devices()
    print("Cleanup completed!")
