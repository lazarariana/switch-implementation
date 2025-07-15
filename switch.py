#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
import os
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

MULTICAST_MAC = bytes([0x01, 0x80, 0xc2, 0, 0, 0])
LLC_HDR = bytes([0x42, 0x42, 0x03])
MULTICAST_MAC_STR = "01:80:c2:00:00:00"
switch_interfaces = dict()

def create_interface(vlan_id, type, port_name, state):
    return {
        'vlan_id': vlan_id,
        'type': type,
        'name': port_name,
        'state': state
    }

switch_config = {
    'own_bridge_ID': 0,
    'root_ID': 0,
    'root_path_cost': 0,
    'root_port': -1
}

# DEBUGGING = True
DEBUGGING = False

def debug (msg):
   if DEBUGGING:
      print (msg)

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def parse_bdpu_header(data):
    bdpu_header = data[21:]
    root_ID = int.from_bytes(bdpu_header[1:2], "big")
    root_path_cost = int.from_bytes(bdpu_header[9:13], "big")
    sender_ID = int.from_bytes(bdpu_header[13:14], "big")
    return root_ID, root_path_cost, sender_ID

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def create_bdpu_packet(config):
    bdpu_packet = {
        'dst_mac': MULTICAST_MAC,
        'src_mac': get_switch_mac(),
        'ether_len': struct.pack('!H', 38),
        'llc': LLC_HDR,
        'root_ID': struct.pack('!B', config['root_ID']),
        'root_path_cost': struct.pack('!I', config['root_path_cost']),
        'own_bridge_ID': struct.pack('!B', config['own_bridge_ID'])
    }

    packet_bytes = (
        bdpu_packet['dst_mac'] +
        bdpu_packet['src_mac'] +
        bdpu_packet['ether_len'] +
        bdpu_packet['llc'] +
        bytes(5) +
        bdpu_packet['root_ID'] +
        bytes(1) +
        bdpu_packet['src_mac'] +
        bdpu_packet['root_path_cost'] +
        bdpu_packet['own_bridge_ID'] +
        bytes(1) +
        bdpu_packet['src_mac'] +
        bytes(10)
    )

    return packet_bytes

# implementation of pseudocode every second send BDPU
def send_bdpu_every_sec():
    while True:
        debug("----- Send BDPU -----")
        if (switch_config['own_bridge_ID'] == switch_config['root_ID']):
            debug ("!!!!root_ID!!!!")
            bdpu_packet = create_bdpu_packet(switch_config)
            for sw_intf in switch_interfaces:
                debug(f'Try to send to interface {switch_interfaces[sw_intf]["name"]}')
                if switch_interfaces[sw_intf]['type'] == "T":
                    debug(f'Send to interface {switch_interfaces[sw_intf]["name"]}')
                    send_to_link(sw_intf, len(bdpu_packet), bdpu_packet)
        time.sleep(1) 

# IEEE 802.1Q VLAN Tagging
def forward_frame(interface, length, data, vlan_tag_length, vlan_tag_frame, vlan_id):
    if switch_interfaces[interface]['type'] == "T" and switch_interfaces[interface]['state'] == 1:
        debug("TRUNK interface not blocked")
        send_to_link(interface, vlan_tag_length, vlan_tag_frame)
    if switch_interfaces[interface]['vlan_id'] == vlan_id:
        debug("Access interface with VLAN_ID match")
        send_to_link(interface, length, data)

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    switch_mac_table = dict()

    filename = "configs/switch" + switch_id + ".cfg"
    # print(sys.argv)

    if not os.path.exists(filename):
        # print(f'Input file {filename} not available')
        exit()

    file = open(filename,'r')
    lines = file.readlines()

    switch_priority = int(lines[0].split()[0])

    for index, line in enumerate(lines[1:]):
        if_name = line.split()[0]
        vlan_id = line.split()[1]
        if (vlan_id != "T"):
            # "A" - access type interface connects a host to the switch
            switch_interfaces[index] = create_interface(int(vlan_id), "A", if_name, 1)
        else:
            # "T" - trunk type interface supports sending frames from multiple VLANs, used between switches
            switch_interfaces[index] = create_interface(0, "T", if_name, 1)

        debug(f'{switch_interfaces[index]["vlan_id"]} ---- {switch_interfaces[index]["name"]} ---- {switch_interfaces[index]["type"]} ---- {switch_interfaces[index]["state"]}')

    file.close()

    switch_config['own_bridge_ID'] = switch_priority
    switch_config['root_ID'] = switch_priority
    
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces_range = range(0, num_interfaces)

    # print("# Starting switch with id {}".format(switch_id), flush=True)
    # print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    # for i in interfaces_range:
    #     print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        # print(f'Destination MAC: {dest_mac}')
        # print(f'Source MAC: {src_mac}')
        # print(f'EtherType: {ethertype}')
        # print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        switch_mac_table[src_mac] = interface
        if dest_mac == MULTICAST_MAC_STR:
            debug(">>>>>> MULTICAST message <<<<<<")
            root_ID, root_path_cost, sender_ID = parse_bdpu_header(data)
            debug(f'>>>>>> root_ID: {root_ID}, root_path_cost: {root_path_cost}, sender_ID: {sender_ID}')
            
            # implementation of pseudocode on receiving a BPDU
            if root_ID < switch_config['root_ID']:
                debug(">>>>>> Lower ROOT_ID")
                switch_config['root_ID'] = root_ID
                switch_config['root_path_cost'] = root_path_cost + 10
                switch_config['root_port'] = interface

                # set all interfaces not to hosts to blocking except the root port
                for sw_intf in switch_interfaces:
                    if switch_interfaces[sw_intf]['type'] == "T" and sw_intf != switch_config['root_port']:
                        debug(f'       >>>>>> disable interface {interface}')
                        switch_interfaces[sw_intf]['state'] = 0

                # Update and forward this BPDU to all other trunk ports
                for sw_intf in switch_interfaces:
                    if switch_interfaces[sw_intf]['type'] == "T" and sw_intf != interface:
                        bdpu_packet = create_bdpu_packet(switch_config)
                        send_to_link(sw_intf, len(bdpu_packet), bdpu_packet)                  
            elif root_ID == switch_config['root_ID']:
                debug(">>>>>> Same ROOT_ID")
                if switch_interfaces == switch_config['root_port'] and root_path_cost + 10 < switch_config['root_path_cost']:
                    switch_config['root_path_cost'] = root_path_cost + 10
                elif switch_interfaces != switch_config['root_port']:
                    # verify designated
                    if root_path_cost > switch_config['root_path_cost']:
                        switch_interfaces[interface]['state'] = 1
            elif sender_ID == switch_config['own_bridge_ID']:
                debug(f'       >>>>>> disable interface {interface}')
                # set to blocking
                switch_interfaces[interface]['state'] = 0

            if switch_config['own_bridge_ID'] == switch_config['root_ID']:
                switch_config['root_port'] = -1            
                # set as designated port
                for sw_intf in switch_interfaces:
                    debug(f'       >>>>>> Enable interface {interface}')
                    switch_interfaces[sw_intf]['state'] = 1
        else:
            debug(">>>>>> UNICAST or BROADCAST message <<<<<<")
            if vlan_id == -1:
                debug("Access interface")
                vlan_id = switch_interfaces[interface]['vlan_id']
                vlan_tag_frame = b''.join([data[:12], create_vlan_tag(vlan_id), data[12:]])
            else:
                debug("came from TRUNK interface")
                vlan_tag_frame = data
                data = b''.join([data[:12], data[16:]])
                length = length - 4

            vlan_tag_length = length + 4
            
            # pseudocode MAC table
            if dest_mac in switch_mac_table:
                debug("Found DEST_MAC in switch_mac_table")
                forward_frame(switch_mac_table[dest_mac], length, data, vlan_tag_length, vlan_tag_frame, vlan_id)
            else:
                debug("DEST_MAC !!! NOT FOUND !!! in switch_mac_table")
                for o in switch_interfaces:
                    if o != interface:
                        forward_frame(o, length, data, vlan_tag_length, vlan_tag_frame,vlan_id)

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()