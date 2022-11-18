#!/usr/bin/python
# -*- coding: utf-8 -*-

##############################################################
#  Script     : Forti_Get_Routes_VPN.py
#  Author     : Valentin CARETTE
#  Date       : 18/11/2022
##############################################################

###########################################################
import datetime
from datetime import timedelta
import time
import os
import re
import sys
import copy
import subprocess
import paramiko

from argparse import ArgumentParser, ArgumentError
from functools import wraps


######################################
####         Functions            ####
######################################

# Argument parser
# My own ArgumentParser with single-line stdout output and unknown state Nagios retcode
class NagiosArgumentParser(ArgumentParser):
    def error(self, message):
        sys.stdout.write('UNKNOWN: Bad arguments (see --help): %s\n' % message)
        sys.exit(3)
# Nagios unknown exit decorator in case of TB
def tb2unknown(method):
    @wraps(method)
    def wrapped(*args, **kw):
        try:
            f_result = method(*args, **kw)
            return f_result
        except Exception, e:
            print 'UNKNOWN: Got exception while running %s: %s' % (method.__name__, str(e))
            if debug:
                raise
            sys.exit(3)
    return wrapped



# Arguments handler
@tb2unknown
def parse_args():
    argparser = NagiosArgumentParser(description='Fortigate - Check the number of IP addresses banned by IPS')
    argparser_global = argparser.add_argument_group('Global')
    argparser_global.add_argument('-H', '--host',       type=str,     required=True,
                           help='Hostname or address to query (mandatory)')
    argparser_global.add_argument('--sshlogin',type=str ,    default='admin',
                           help='user used for ssh session')
    argparser_global.add_argument('--sshpassword',type=str ,    default='switch',
                           help='password used for ssh session')
    argparser_global.add_argument('--sshport',type=int ,    default=22,
                           help='SSH port')
    argparser_global.add_argument('-w', '--warning',       type=int,    default=50,
                           help='Warning number of banned IP addresses')
    argparser_global.add_argument('-c', '--critical',       type=int,   default=100,
                           help='Critical number of banned IP addressess')
    argparser_global.add_argument('-D', '--debug',       type=str,     default='no',
                           help='ssh session print to stdout: yes')
    args = argparser.parse_args()
    return args

@tb2unknown
def ssh_run_remote_command(host, ssh_username, ssh_password, cmd):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=host,
                           username=ssh_username,
                           password=ssh_password)
        for commands in CLICommands:
            stdin, stdout, stderr = ssh_client.exec_command(cmd)

        out = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        if error:
            raise Exception('There was an error pulling the runtime: {}'.format(error))
        ssh_client.close()

        return out

def exec_command(self, command, bufsize=-1):
    #print "Executing Command: "+command
    chan = self._transport.open_session()
    chan.exec_command(command)
    stdin = chan.makefile('wb', bufsize)
    stdout = chan.makefile('rb', bufsize)
    stderr = chan.makefile_stderr('rb', bufsize)
    return stdin, stdout, stderr


if __name__ == '__main__':
    debug = False
    # Get inputs from input arguments
    inputs = parse_args()
    StatusExpiredLong = 0
    vdom = []

    # SSH connection
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=inputs.host,
                       username=inputs.sshlogin,
                       password=inputs.sshpassword,
                       port=inputs.sshport,
                       timeout=20)
    SSH_Session = ssh_client.invoke_shell()

    stdin, stdout, stderr = ssh_client.exec_command('diagnose sys vd list')
    out = stdout.read().decode().strip()
    error = stderr.read().decode().strip()
    if 'Cannot read termcap database' in error:
        pass
    elif error:
        if 'Command fail' in error:
            SSH_Session.send('config global\n')
            time.sleep(0.1)
            SSH_Session.send('diagnose sys vd list\n')
            time.sleep(0.1)
            out = SSH_Session.recv(65535)
            out = out.decode("utf-8")
            SSH_Session.send('end\n')
            for line in out.splitlines():
                if "name=" in line:
                   vdom.append(str(line.split(" ")[0].split("=")[1].split("/")[0]))
            vdom = [str(r) for r in vdom]
            for vd in ['vsys_ha', 'vsys_hamgmt', 'vsys_fgfm', 'dmgmt-vdom']:
                vdom.remove(vd)
            for vd in vdom:
                SSH_Session.send('config vdom\n')
                time.sleep(0.1)
                SSH_Session.send('edit ' + vd + '\n')
                time.sleep(0.1)
                SSH_Session.send('get router info routing-table all\n')
                time.sleep(0.1)
                SSH_Session.send('get vpn ipsec tunnel summary\n')
                time.sleep(0.1)
                SSH_Session.send('end\n')
            out = SSH_Session.recv(65535)
            out = out.decode("utf-8")
            ssh_client.close()
            id = -1
            vd_routes = [0] * len(vdom)
            vd_vpn = [0] * len(vdom)
            for line in out.splitlines():
                if line != "" and "--More--" not in line and "config vdom" not in line:
                    if "edit" in line:
                        print("############################################################")
                        print(line.split("edit ")[1])
                        print("############################################################")
                        id += 1
                    elif "#" not in line:
                        print(line)
                    if "is directly" in line or "via" in line:
                        vd_routes[id] += 1
                    if "VPN" in line:
                        vd_vpn[id] += 1

            print("___________________________________________")
            print("SUMMARY:")
            print("___________________________________________")
            for id in range(len(vdom)):
                print(str(vdom[id] + ":"))
                print("_______Routes: " + str(vd_routes[id]))
                print("_______VPN: " + str(vd_vpn[id]))
#            print(out)
        else:
            raise Exception('There was an error pulling the runtime: {}'.format(error))
            sys.ext(3)
            print('Unknown - Error with SSH Session')
