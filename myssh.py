#!/usr/bin/python

import os
import paramiko
import argparse
import configparser
from scp import SCPClient

#Content of ssh_env.py
SSH_CONFIG_FILE=os.environ['HOME'] + "/.ssh.ini"
CONFIG_NAME="SSH"
SSH_USER_STR="User"
SSH_PASSWORD_STR="Password"
my_user=""
my_password=""

def initSSHPass():
   global my_user
   global my_password

   if os.path.isfile(SSH_CONFIG_FILE):
      config = configparser.RawConfigParser()
      config.read(SSH_CONFIG_FILE)
      my_user = config.get(CONFIG_NAME, SSH_USER_STR)
      my_password = config.get(CONFIG_NAME, SSH_PASSWORD_STR)
   else:
      print "%s not found!" %(SSH_CONFIG_FILE)

def execSSHCommand(ip_addr, cmd):
  try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip_addr, username=my_user, password=my_password)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
    data = ssh_stdout.read().splitlines()
    for line in data:
      print line
  finally:
    ssh.close()

def createSCPClient(server):
  client = paramiko.SSHClient()
  #client.load_system_host_keys()
  client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  client.connect(server, username=my_user, password=my_password)
  scp = SCPClient(client.get_transport())
  return scp

def closeSCPClient(scp):
  scp.close()
    

