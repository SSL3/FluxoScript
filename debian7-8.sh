#!/bin/bash

# ==================================================

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# Install lolcat
apt-get install bc -y
apt-get install xfonts-thai* -y
apt-get install figlet
apt-get install ruby -y
apt-get install unzip
wget https://github.com/busyloop/lolcat/archive/master.zip
cd lolcat-master/bin
gem install lolcat
cd
rm -r lolcat-master
rm master.zip

# go to root
cd

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# install wget and curl
apt-get update;apt-get -y install wget curl;

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Bangkok /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# set repo
wget -O /etc/apt/sources.list "https://github.com/SSL3/FluxoScript/raw/master/sources.list.debian7"
wget "http://www.dotdeb.org/dotdeb.gpg"
wget "http://www.webmin.com/jcameron-key.asc"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# update
apt-get update

# install webserver
apt-get -y install nginx

# install essential package
apt-get -y install nano iptables dnsutils openvpn screen whois ngrep unzip unrar

# install neofetch
echo "deb http://dl.bintray.com/dawidd6/neofetch jessie main" | sudo tee -a /etc/apt/sources.list
curl -L "https://bintray.com/user/downloadSubjectPublicKey?username=bintray" -o Release-neofetch.key && sudo apt-key add Release-neofetch.key && rm Release-neofetch.key
apt-get update
apt-get install neofetch

echo "clear" >> .bashrc
echo 'echo -e "\e[01;35m$(figlet -ckf smslant cyox.ga)\e[00m" | lolcat' >> .bashrc
echo 'echo -e "\e[01;35m$(figlet -ckf term Welcome to the server $HOSTNAME)\e[00m" | lolcat' >> .bashrc
echo 'echo -e "\e[01;35m$(figlet -ckf term Script by oxide)\e[00m" | lolcat' >> .bashrc
echo 'echo -e "\e[01;35m$(figlet -ckf term I am a slow walker, but I never walk back.)\e[00m" | lolcat' >> .bashrc
echo 'echo -e "\e[01;35m$(figlet -ckf term Line:oxide.x)\e[00m" | lolcat' >> .bashrc
echo 'echo -e "\e[01;35m$(figlet -ckf term .........................)\e[00m" | lolcat' >> .bashrc
echo 'echo -e ""' >> .bashrc
echo 'menu' >> .bashrc
# webmin
apt-get -y install webmin
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://github.com/SSL3/FluxoScript/raw/master/nginx.conf"
mkdir -p /home/vps/public_html
echo "<pre>Setup by oxide@cyox.ga</pre>" > /home/vps/public_html/index.html
wget -O /etc/nginx/conf.d/vps.conf "https://github.com/SSL3/FluxoScript/raw/master/vps.conf"
service nginx restart

# install openvpn
wget -O /etc/openvpn/openvpn.tar "https://github.com/SSL3/FluxoScript/raw/master/openvpn-debian.tar"
cd /etc/openvpn/
tar xf openvpn.tar
wget -O /etc/openvpn/1194.conf "https://github.com/SSL3/FluxoScript/raw/master/1194.conf"
service openvpn restart
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
iptables-save > /etc/iptables_yg_baru_dibikin.conf
wget -O /etc/network/if-up.d/iptables "https://github.com/SSL3/OrangSabahan007/raw/master/iptables"
chmod +x /etc/network/if-up.d/iptables
service openvpn restart

# config openvpn
cd /etc/openvpn/
wget -O /etc/openvpn/client.ovpn "https://github.com/SSL3/FluxoScript/raw/master/client-1194.conf"
sed -i $MYIP2 /etc/openvpn/client.ovpn;
cp client.ovpn /home/vps/public_html/

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://github.com/SSL3/FluxoScript/raw/master/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://github.com/SSL3/FluxoScript/raw/master/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# install mrtg
wget -O /etc/snmp/snmpd.conf "http://script.hostingtermurah.net/repo/snmpd.conf"
wget -O /root/mrtg-mem.sh "http://script.hostingtermurah.net/repo/mrtg-mem.sh"
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "http://script.hostingtermurah.net/repo/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# setting port ssh
cd
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
service ssh restart

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 80"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart

# install Fail2ban
apt-get -y install fail2ban;service fail2ban restart

# install vnstat
sudo apt-get install vnstat -y
vnstat -u -i eth0
sudo /etc/init.d/vnstat start

# install squid3
cd
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "https://github.com/SSL3/FluxoScript/raw/master/squid3.conf"
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

# color text
cd
rm -rf /root/.bashrc
wget -O /root/.bashrc "https://github.com/SSL3/OrangSabahan007/raw/master/.bashrc"

# install lolcat
sudo apt-get -y install ruby
sudo gem install lolcat

# download script
cd
wget -O /usr/bin/motd "https://github.com/SSL3/OrangSabahan007/raw/master/motd"
wget -O /usr/bin/benchmark "https://github.com/SSL3/OrangSabahan007/raw/master/benchmark.sh"
wget -O /usr/bin/speedtest "https://github.com/SSL3/OrangSabahan007/raw/master/speedtest_cli.py"
wget -O /usr/bin/ps-mem "https://github.com/SSL3/OrangSabahan007/raw/master/ps_mem.py"
wget -O /usr/bin/dropmon "https://github.com/SSL3/OrangSabahan007/raw/master/dropmon.sh"
wget -O /usr/bin/menu "https://github.com/SSL3/OrangSabahan007/raw/master/menu.sh"
wget -O /usr/bin/user-active-list "https://github.com/SSL3/OrangSabahan007/raw/master/user-active-list.sh"
wget -O /usr/bin/user-add "https://github.com/SSL3/OrangSabahan007/raw/master/user-add.sh"
wget -O /usr/bin/user-add-pptp "https://raw.githubusercontent.com/sslmode/sslmode/master/tools/user-add-pptp.sh"
wget -O /usr/bin/user-del "https://github.com/SSL3/OrangSabahan007/raw/master/user-del.sh"
wget -O /usr/bin/disable-user-expire "https://github.com/SSL3/OrangSabahan007/raw/master/disable-user-expire.sh"
wget -O /usr/bin/delete-user-expire "https://github.com/SSL3/OrangSabahan007/raw/master/delete-user-expire.sh"
wget -O /usr/bin/banned-user "https://github.com/SSL3/OrangSabahan007/raw/master/banned-user.sh"
wget -O /usr/bin/unbanned-user "https://github.com/SSL3/OrangSabahan007/raw/master/unbanned-user.sh"
wget -O /usr/bin/user-expire-list "https://github.com/SSL3/OrangSabahan007/raw/master/user-expire-list.sh"
wget -O /usr/bin/user-gen "https://raw.githubusercontent.com/sslmode/sslmode/master/tools/user-gen.sh"
wget -O /usr/bin/userlimit.sh "https://github.com/SSL3/OrangSabahan007/raw/master/userlimit.sh"
wget -O /usr/bin/userlimitssh.sh "https://github.com/SSL3/OrangSabahan007/raw/master/userlimitssh.sh"
wget -O /usr/bin/user-list "https://github.com/SSL3/OrangSabahan007/raw/master/user-list.sh"
wget -O /usr/bin/user-login "https://github.com/SSL3/OrangSabahan007/raw/master/user-login.sh"
wget -O /usr/bin/user-pass "https://github.com/SSL3/OrangSabahan007/raw/master/user-pass.sh"
wget -O /usr/bin/user-renew "https://github.com/SSL3/OrangSabahan007/raw/master/user-renew.sh"
wget -O /usr/bin/clearcache.sh "https://github.com/SSL3/OrangSabahan007/raw/master/clearcache.sh"
wget -O /usr/bin/bannermenu "https://github.com/SSL3/OrangSabahan007/raw/master/bannermenu"
cd

#rm -rf /etc/cron.weekly/
#rm -rf /etc/cron.hourly/
#rm -rf /etc/cron.monthly/
rm -rf /etc/cron.daily/
wget -O /root/passwd "https://github.com/SSL3/OrangSabahan007/raw/master/passwd.sh"
chmod +x /root/passwd
echo "01 23 * * * root /root/passwd" > /etc/cron.d/passwd

echo "*/30 * * * * root service dropbear restart" > /etc/cron.d/dropbear
echo "00 23 * * * root /usr/bin/disable-user-expire" > /etc/cron.d/disable-user-expire
echo "0 */12 * * * root /sbin/reboot" > /etc/cron.d/reboot
#echo "00 01 * * * root echo 3 > /proc/sys/vm/drop_caches && swapoff -a && swapon -a" > /etc/cron.d/clearcacheram3swap
echo "*/30 * * * * root /usr/bin/clearcache.sh" > /etc/cron.d/clearcache1

cd
chmod +x /usr/bin/motd
chmod +x /usr/bin/benchmark
chmod +x /usr/bin/speedtest
chmod +x /usr/bin/ps-mem
#chmod +x /usr/bin/autokill
chmod +x /usr/bin/dropmon
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-active-list
chmod +x /usr/bin/user-add
chmod +x /usr/bin/user-add-pptp
chmod +x /usr/bin/user-del
chmod +x /usr/bin/disable-user-expire
chmod +x /usr/bin/delete-user-expire
chmod +x /usr/bin/banned-user
chmod +x /usr/bin/unbanned-user
chmod +x /usr/bin/user-expire-list
chmod +x /usr/bin/user-gen
chmod +x /usr/bin/userlimit.sh
chmod +x /usr/bin/userlimitssh.sh
chmod +x /usr/bin/user-list
chmod +x /usr/bin/user-login
chmod +x /usr/bin/user-pass
chmod +x /usr/bin/user-renew
chmod +x /usr/bin/clearcache.sh
chmod +x /usr/bin/bannermenu
cd
#Block Torrent
iptables -A OUTPUT -p tcp --dport 6881:6889 -j DROP
iptables -A OUTPUT -p udp --dport 1024:65534 -j DROP
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP


# Finished
cd
chown -R www-data:www-data /home/vps/public_html
service nginx start
service openvpn restart
service cron restart
service ssh restart
service dropbear restart
service squid3 restart
service fail2ban restart
service webmin restart
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# info
clear
echo "Autoscript Include:"  | tee log-install.txt | lolcat
echo "==========================================="  | tee -a log-install.txt | lolcat
echo ""  | tee -a log-install.txt
echo "Service"  | tee -a log-install.txt | lolcat
echo "-------"  | tee -a log-install.txt | lolcat
echo "OpenSSH  : 22, 143"  | tee -a log-install.txt | lolcat
echo "Dropbear : 80, 443"  | tee -a log-install.txt | lolcat
echo "Squid3   : 8080, 3128, 993 (limit to IP)"  | tee -a log-install.txt | lolcat
echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:81/client.ovpn)"  | tee -a log-install.txt | lolcat
echo "badvpn   : badvpn-udpgw port 7300"  | tee -a log-install.txt | lolcat
echo "nginx    : 81"  | tee -a log-install.txt | lolcat
echo ""  | tee -a log-install.txt
echo "Script"  | tee -a log-install.txt | lolcat
echo "------"  | tee -a log-install.txt | lolcat
echo "[0]       (change menu to Thai)"  | tee -a log-install.txt | lolcat
echo "menu      (Displays a list of available commands)"  | tee -a log-install.txt | lolcat
echo "usernew   (Creating an Account)"  | tee -a log-install.txt | lolcat
echo "trial     (Create a Trial Account)"  | tee -a log-install.txt | lolcat
echo "del       (Clearing Account)"  | tee -a log-install.txt | lolcat
echo "exp       (Clearing Account Expired)" | tee -a log-install.txt | lolcat
echo "check     (Check User Login)"  | tee -a log-install.txt | lolcat
echo "member    (Check Member)"  | tee -a log-install.txt | lolcat
echo "backup    (backup All-User)"  | tee -a log-install.txt | lolcat
echo "restore   (restore All-User)"  | tee -a log-install.txt | lolcat
echo "res       (Restart Service All)"  | tee -a log-install.txt | lolcat
echo "reboot    (Reboot Server)"  | tee -a log-install.txt | lolcat
echo "speedtest (Speedtest Server)"  | tee -a log-install.txt | lolcat
echo "bw        (Bandwidth Management)"  | tee -a log-install.txt | lolcat
echo "vn        (Bandwidth Checklimit)"  | tee -a log-install.txt | lolcat
echo "info      (Displays System Information)"  | tee -a log-install.txt | lolcat
echo "about     (Information about auto install script)"  | tee -a log-install.txt | lolcat
echo ""  | tee -a log-install.txt
echo "Other Features"  | tee -a log-install.txt | lolcat
echo "----------"  | tee -a log-install.txt | lolcat
echo "Webmin   : http://$MYIP:10000/"  | tee -a log-install.txt | lolcat
echo "Timezone : Asia/Bangkok (GMT +7)"  | tee -a log-install.txt | lolcat
echo "Fail2Ban : [on]" | tee -a log-install.txt | lolcat
echo "IPv6     : [off]"  | tee -a log-install.txt | lolcat
echo ""  | tee -a log-install.txt
echo "Log Install --> /root/log-install.txt"  | tee -a log-install.txt | lolcat
echo ""  | tee -a log-install.txt
echo "Created By oxide@cyox.ga"  | tee -a log-install.txt | lolcat
echo ""  | tee -a log-install.txt
echo "VPS AUTO REBOOT 03:00"  | tee -a log-install.txt | lolcat
echo ""  | tee -a log-install.txt
echo "==========================================="  | tee -a log-install.txt | lolcat
cat /dev/null > ~/.bash_history && history -c
