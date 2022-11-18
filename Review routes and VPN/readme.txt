This script returns the list of routes and VPN for each VDOM and a summary with the number of such items by VDOM.
It runs in python 2.7 and requires the module python-paramiko.

Usage: 
python Forti_Get_Routes_VPN.py -H IP --sshlogin user --sshpassword password --sshport 22
