#!/bin/bash

# Adding a new TUN device named asa0
sudo ip tuntap add dev asa0 mode tun

# Assigning an IP address to the device
sudo ip addr add 10.0.1.2/24 dev asa0

# Bringing the device up
sudo ip link set dev asa0 up

# Display network interface configuration
ifconfig
