#!/bin/bash
# Script restart service dropbear, webmin, squid3, openvpn, openssh
# 
service dropbear restart
service squid3 restart
service ssh restart
#service webmin restart
service openvpn restart
