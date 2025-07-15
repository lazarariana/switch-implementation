Switch Implementation

- I used the python skel and wrapper functions provided on gitlab
- Implementation:

1. MAC table
 - If the switch receives a new frame on an interface, it will use source and destination
MAC addresses from Ethernet header of the frame to update the MAC table. MAC table role is
binding receiving interface with the source MAC address.
- For the source MAC address, the entry will be added into the MAC table if not found or
updated if it already existed.
- For the destination MAC address, the switch first checks if it is unicast or multicast. In
unicast case the frame is sent to the corresponding interface from MAC table if it exists. If
this entry was not in the table or the destination is multicast, the frame will be sent to all
the other interfaces (flood).

2. VLAN
- Interfaces are attached to one or more VLANs
- A switch can support multiple VLANs, ensuring sending frames with broadcast or not found
destination only to the interfaces which belong to that VLAN.
- The switch has 2 types of interfaces:
  - access type interface which connects a host to the switch
  - trunk type interface which supports sending frames from multiple VLANs, used between switches
- A frame will be forwarded:
    - with the 802.1Q header if transmitted on a trunk interface of a switch. If the frame was
received from an access interface, the switch must add the 802.1Q header.
    - without the 802.1Q header if it is transmitted on an access interface and VLAN ID is equal to
the source interface one.
    
3. STP
- Interfaces states: Blocking and Listening.
- Frames transmitted are called BPDU - Bridge Protocol Data Units. Important components: root ID,
sender ID, root path cost.
- In the beginning all switches are considered root bridge. Selected root bridge has minimum ID.
Designated ports forward frames to it. (minimum root_path_cost)
- Config file contains the priority of each switch.
- Access interfaces remain listening, cannot cause loops.
- Trunk interfaces may cause loops, therefore:
    - blocking ports do not forward BPDU to prevent that.
    - root and designated ports are in listening mode, sending frames.
