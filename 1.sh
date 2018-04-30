#!/bin/bash
echo -e "\e[40;38;5;226m " 
echo " WELCOME TO AUTOSCRIPT VpsProject "
echo "################################################################################" 
echo "#                                                                              #" 
echo "#      SSSSSSSSSSSSSSSSS  sssssssssssssssss  HHHHHHHHH        HHHHHHHHH        #" 
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHH        HHHHHHHHH        #" 
echo "#      SSSSSS             SSSSSS             HHHHHHHHH        HHHHHHHHH        #" 
echo "#      SSSSSS             SSSSSS             HHHHHHHHH        HHHHHHHHH        #" 
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHHHHHHHHHHHHHHHHHHH        #" 
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHHHHHHHHHHHHHHHHHHH        #" 
echo "#                 SSSSSS             SSSSSS  HHHHHHHHH        HHHHHHHHH        #" 
echo "#                 SSSSSS             SSSSSS  HHHHHHHHH        HHHHHHHHH        #"
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHH        HHHHHHHHH        #" 
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHH        HHHHHHHHH        #" 
echo "#------------------------------------------------------------------------------#" 
echo "#          SELAMAT DATANG DI SCRIPT AUTO SETUP VPS BY VPSPROJECT.              #" 
echo "#                       SCRIPT VERSION V2.0 FOR DEBIAN 7-8-9                   #"
echo "#                               SEMOGA BERMANFAAT                              #" 
echo "#------------------------------------------------------------------------------#" 
echo "################################################################################"
echo "========================================"
echo "CLICK 'I' SETUP VPS Non-Local"
echo "CLICK 'L' SETUP VPS Local" 
echo "========================================"
read -p "Location : " -e loc
apt-get update

if [[ $USER != "root" ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
#MYIP=$(wget -qO- ipv4.icanhazip.com);

# get the VPS IP
#ip=`ifconfig venet0:0 | grep 'inet addr' | awk {'print $2'} | sed s/.*://`

#MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
MYIP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
if [ "$MYIP" = "" ]; then
	MYIP=$(wget -qO- ipv4.icanhazip.com)
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [[ $ether = "" ]]; then
        ether=eth0
fi

#vps="zvur";
vps="blangkon";

#if [[ $vps = "zvur" ]]; then
	#source="http://"
#else
	source="http://vpsproject.me/Debian7"
#fi

# go to root
cd
echo "=============================="
echo "        MULA SETUP        "
echo "=============================="
echo -e "\e[40;38;5;101m "    
# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
#sed -i 's/net.ipv6.conf.all.disable_ipv6 = 0/net.ipv6.conf.all.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.default.disable_ipv6 = 0/net.ipv6.conf.default.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.lo.disable_ipv6 = 0/net.ipv6.conf.lo.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.eth0.disable_ipv6 = 0/net.ipv6.conf.eth0.disable_ipv6 = 1/g' /etc/sysctl.conf
#sysctl -p
echo -e "\e[40;38;5;226 " 
echo "=============================="
echo "     INSTALL CURL     "
echo "=============================="
# install wget and curl
apt-get update;apt-get -y install wget curl;
apt-get install gem
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime
# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart
# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y --purge remove dropbear*;
#apt-get -y autoremove;
echo -e "\e[40;38;5;101m " 
echo "=============================="
echo "       REPO "
echo "=============================="
# set repo
ver=`cat /etc/debian_version`
if [ $ver = '6.0' ]
then
debver='6'
elif [ $ver = '6.1' ]
then
debver='6'
elif [ $ver = '6.2' ]
then
debver='6'
elif [ $ver = '6.3' ]
then
debver='6'
elif [ $ver = '6.4' ]
then
debver='6'
elif [ $ver = '6.5' ]
then
debver='6'
elif [ $ver = '6.6' ]
then
debver='6'
elif [ $ver = '6.7' ]
then
debver='6'
elif [ $ver = '6.8' ]
then
debver='6'
elif [ $ver = '6.9' ]
then
debver='6'
elif [ $ver = '7.0' ]
then no
debver='7'
elif [ $ver = '7.1' ]
then
debver='7'
elif [ $ver = '7.2' ]
then
debver='7'
elif [ $ver = '7.3' ]
then
debver='7'
elif [ $ver = '7.4' ]
then
debver='7'
elif [ $ver = '7.5' ]
then
debver='7'
elif [ $ver = '7.6' ]
then
debver='7'
elif [ $ver = '7.7' ]
then
debver='7'
elif [ $ver = '7.8' ]
then
debver='7'
elif [ $ver = '7.9' ]
then
debver='7'
elif [ $ver = '8.0' ]
then
debver='8'
elif [ $ver = '8.1' ]
then
debver='8'
elif [ $ver = '8.2' ]
then
debver='8'
elif [ $ver = '8.3' ]
then
debver='8'
elif [ $ver = '8.4' ]
then
debver='8'
elif [ $ver = '8.5' ]
then
debver='8'
elif [ $ver = '8.6' ]
then
debver='8'
elif [ $ver = '8.7' ]
then
debver='8'
elif [ $ver = '8.8' ]
then
debver='8'
elif [ $ver = '8.9' ]
then
debver='8'
else
debver='Null'
fi
if [ $debver = '6' ]; then
	if [[ "$loc" = "I" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian7
		wget $source/dotdeb.gpg
		cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
	elif [[ "$loc" = "L" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian7.local
		wget $source/dotdeb.gpg
		apt-key add dotdeb.gpg
		rm dotdeb.gpg
		apt-get install python-software-properties 
		apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
	elif [[ "$loc" = "i" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian7
		wget $source/dotdeb.gpg
		cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
    elif [[ "$loc" = "l" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian7.local
		wget $source/dotdeb.gpg
		apt-key add dotdeb.gpg
		rm dotdeb.gpg
		apt-get install python-software-properties 
		apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
	fi
elif [ $debver = '7' ]; then
	if [[ "$loc" = "I" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian7
		wget $source/dotdeb.gpg
		cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
    elif [[ "$loc" = "L" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian7.local
		wget $source/dotdeb.gpg
		apt-key add dotdeb.gpg
		rm dotdeb.gpg
		apt-get install python-software-properties 
		apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
	elif [[ "$loc" = "i" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian7
		wget $source/file/dotdeb.gpg
		cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
    apt-get update
	elif [[ "$loc" = "l" ]]; then
		wget -O /etc/apt/sources.list $source/sources.debian7.local
		wget $source/dotdeb.gpg
		apt-key add dotdeb.gpg
		rm dotdeb.gpg
		apt-get install python-software-properties 
		apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
fi  	
elif [ $debver = '8' ]; then
	if [[ "$loc" = "I" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian8
		wget $source/dotdeb.gpg
		cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
	elif [[ "$loc" = "L" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian8.local
		wget $source/dotdeb.gpg
		apt-key add dotdeb.gpg
		rm dotdeb.gpg
		apt-get install python-software-properties 
		apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
    apt-get update
	elif [[ "$loc" = "i" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian8
		wget $source/dotdeb.gpg
		cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
	elif [[ "$loc" = "l" ]]; then
		wget -O /etc/apt/sources.list $source/sources.list.debian8.local
		wget $source/dotdeb.gpg
		apt-key add dotdeb.gpg
		rm dotdeb.gpg
		apt-get install python-software-properties 
		apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xcbcb082a1bb943db
		cd /root
		wget http://www.webmin.com/jcameron-key.asc
		apt-key add jcameron-key.asc
		cd
		apt-get update
	fi
else
	cd
fi

gpg --keyserver pgpkeys.mit.edu --recv-key  9D6D8F6BC857C906      
gpg -a --export 9D6D8F6BC857C906 | sudo apt-key add -
gpg --keyserver pgpkeys.mit.edu --recv-key  7638D0442B90D010      
gpg -a --export 7638D0442B90D010 | sudo apt-key add -

# update
apt-get update;apt-get -y upgrade;

# install webserver
apt-get -y install nginx php5-fpm php5-cli
apt-get -y install zip tar

# install essential package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
apt-get -y install bmon 
apt-get -y install iftop 
apt-get -y install htop 
apt-get -y install nmap 
apt-get -y install axel 
apt-get -y install nano 
apt-get -y install iptables 
apt-get -y install traceroute 
apt-get -y install sysv-rc-conf 
apt-get -y install dnsutils 
apt-get -y install bc 
apt-get -y install nethogs
apt-get -y install openvpn 
apt-get -y install vnstat 
apt-get -y install less 
apt-get -y install screen 
apt-get -y install psmisc 
apt-get -y install apt-file 
apt-get -y install whois 
apt-get -y install ptunnel 
apt-get -y install ngrep 
apt-get -y install mtr 
apt-get -y install git 
apt-get -y install zsh 
apt-get -y install mrtg 
apt-get -y install snmp 
apt-get -y install snmpd 
apt-get -y install snmp-mibs-downloader 
apt-get -y install unzip 
apt-get -y install unrar 
apt-get -y install rsyslog 
apt-get -y install debsums 
apt-get -y install rkhunter
apt-get -y install build-essential
apt-get -y --force-yes -f install libxml-parser-perl
echo -e "\e[40;38;5;226m " 
echo "=============================="
echo "  UPDATE ALL SERVICE        "
echo "=============================="
# disable exim
service exim4 stop
sysv-rc-conf exim4 off
# update apt-file
apt-file update
# setting vnstat
vnstat -u -i $ether
service vnstat restart
#text gambar
apt-get install boxes
# text pelangi
sudo apt-get install ruby
sudo gem install lolcat
# text warna
cd
rm -rf /root/.bashrc
wget -O /root/.bashrc $source/.bashrc
echo -e "\e[40;38;5;202m "
echo "=============================="
echo "      INSTALL WEBSERVER        "
echo "=============================="
# Install Webserver Port 81
apt-get install nginx php5 libapache2-mod-php5 php5-fpm php5-cli php5-mysql php5-mcrypt libxml-parser-perl -y
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.old
curl $source/nginx.conf > /etc/nginx/nginx.conf
curl $source/vps.conf > /etc/nginx/conf.d/vps.conf
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
useradd -m vps;
mkdir -p /home/vps/public_html
echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
chown -R www-data:www-data /home/vps/public_html
chmod -R g+rw /home/vps/public_html
cd /home/vps/public_html
wget -O /home/vps/public_html/uptime.php "http://autoscript.kepalatupai.com/uptime.php1"
wget -O /home/vps/public_html/index.html "http://vpsproject.me/index.html"
service php5-fpm restart
service nginx restart
#echo -e "\e[40;38;5;101m " 
#echo "=============================="
#echo "       INSTALL OPENVPN    "
#echo "=============================="
# install openvpn
#wget -O /etc/openvpn/openvpn.tar $source/openvpn-debian.tar
#cd /etc/openvpn/
#tar xf openvpn.tar
#wget -O /etc/openvpn/1194.conf $source/1194.conf
#service openvpn restart
#sysctl -w net.ipv4.ip_forward=1
#sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
#iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
#iptables-save > /etc/iptables_yg_baru_dibikin.conf
#get -O /etc/network/if-up.d/iptables $source/iptables
#hmod +x /etc/network/if-up.d/iptables
#ervice openvpn restart 

konfigurasi openvpn
#cd /etc/openvpn/
#wget -O /etc/openvpn/client.ovpn $source/client-1194.conf
#sed -i $MYIP2 /etc/openvpn/client.ovpn;
#cp client.ovpn /home/vps/public_html/
echo -e "\e[40;38;5;166m " 
echo "=============================="
echo "        INSTALL MRTG      "
echo "=============================="
# install mrtg
apt-get update;apt-get -y install snmpd;
wget -O /etc/snmp/snmpd.conf $source/snmpd.conf
wget -O /root/mrtg-mem.sh $source/mrtg-mem.sh
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl $source/mrtg.conf >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd
echo -e "\e[40;38;5;101m " 
echo "=============================="
echo "       INSTALL SSH "
echo "=============================="
# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
#sed -i '/Port 22/a Port 80' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
service ssh restart
# update OpenSSH
wget $source/openssh-7.5p1-openssl-1.1.0-1.patch
wget $source/openssh-7.5p1.tar.gz
tar -xf openssh-7.5p1.tar.gz
cd openssh-7.5p1
patch -Np1 -i ../openssh-7.5p1-openssl-1.1.0-1.patch && ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-md5-passwords && make && make install
# configure ssh
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 2020' /etc/ssh/sshd_config
echo -e "\e[40;38;5;126m " 
echo "=============================="
echo "        INSTALL DROPBEAR       "
echo "=============================="
# Install Dropbear
apt-get install zlib1g-dev dpkg-dev dh-make -y
wget $source/dropbear-2014.63.tar.bz2
tar jxvf dropbear-2014.63.tar.bz2
cd dropbear-2014.63
dpkg-buildpackage
cd ..
OS=`uname -m`;
if [ $OS = 'i686' ]; then
	dpkg -i dropbear_2014.63-0.1_i386.deb
elif [ $OS = 'x86_64' ]; then
	dpkg -i dropbear_2014.63-0.1_amd64.deb
fi
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 110 -p 109 -p 80"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart
cd
echo -e "\e[40;38;5;102m " 
echo "=============================="
echo "        INSTALL DROPBEAR       "
echo "=============================="
# bannerssh
wget $source/debian7/bannerssh
mv ./bannerssh /bannerssh
chmod 0644 /bannerssh
service dropbear restart
service ssh restart
cd
echo -e "\e[40;38;5;100m " 
echo "=============================="
echo "        VNSTAT   "
echo "=============================="
# Install VNSTAT
apt-get install vnstat -y
cd /home/vps/public_html/
wget $source/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
if [[ `ifconfig -a | grep "venet0"` ]]
then
cekvirt='OpenVZ'
elif [[ `ifconfig -a | grep "venet0:0"` ]]
then
cekvirt='OpenVZ'
elif [[ `ifconfig -a | grep "venet0:0-00"` ]]
then
cekvirt='OpenVZ'
elif [[ `ifconfig -a | grep "venet0-00"` ]]
then
cekvirt='OpenVZ'
elif [[ `ifconfig -a | grep "eth0"` ]]
then
cekvirt='KVM'
elif [[ `ifconfig -a | grep "eth0:0"` ]]
then
cekvirt='KVM'
elif [[ `ifconfig -a | grep "eth0:0-00"` ]]
then
cekvirt='KVM'
elif [[ `ifconfig -a | grep "eth0-00"` ]]
then
cekvirt='KVM'
fi
if [ $cekvirt = 'KVM' ]; then
	sed -i 's/eth0/eth0/g' config.php
	sed -i "s/\$iface_list = array('eth0', 'sixxs');/\$iface_list = array('eth0');/g" config.php
	sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
	sed -i 's/Internal/Internet/g' config.php
	sed -i "s/\$locale = 'en_US.UTF-8';/\$locale = 'en_US.UTF+8';/g" config.php
	cd
elif [ $cekvirt = 'OpenVZ' ]; then
	sed -i 's/eth0/venet0/g' config.php
	sed -i "s/\$iface_list = array('venet0', 'sixxs');/\$iface_list = array('venet0');/g" config.php
	sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
	sed -i 's/Internal/Internet/g' config.php
	sed -i '/SixXS IPv6/d' config.php
	cd
else
	cd
fi
echo -e "\e[40;38;5;222m " 
echo "=============================="
echo "        INSTALL BADVPN       "
echo "=============================="
# Install BadVPN
apt-get -y install cmake make gcc
wget http://vpsproject.me/site5/Debian7/badvpn-1.999.127.tar.bz2
tar xf badvpn-1.999.127.tar.bz2
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.127 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
screen badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &
cd

#if [[ $ether = "eth0" ]]; then
#	wget -O /etc/iptables.conf $source/Debian7/iptables.up.rules.eth0
#else
#	wget -O /etc/iptables.conf $source/Debian7/iptables.up.rules.venet0
#fi

#sed -i $MYIP2 /etc/iptables.conf;
#iptables-restore < /etc/iptables.conf;

# block all port except
#sed -i '$ i\iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 21 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 53 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 81 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 109 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 110 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 143 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 1194 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 3128 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 8000 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 8080 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp --dport 10000 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p udp -m udp --dport 2500 -j ACCEPT' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p udp -m udp -j DROP' /etc/rc.local
#sed -i '$ i\iptables -A OUTPUT -p tcp -m tcp -j DROP' /etc/rc.local
echo -e "\e[40;38;5;136m " 
echo "=============================="
echo "        INSTALL DDOS"
echo "=============================="
# install fail2ban
apt-get update;apt-get -y install fail2ban;service fail2ban restart;

# Instal (D)DoS Deflate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'
echo -e "\e[40;38;5;101m " 
echo "=============================="
echo "        INSTALL SQUID 3 "
echo "=============================="
# install squid3
#wget -q http://vpsproject.me/site5/Debian7/squid3.sh
#chmod 100 squid3.sh
#./squid3.sh
apt-get -y install squid3
wget -O /etc/squid3/squid.conf $source/squid3.conf
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart
echo -e "\e[40;38;5;27m " 
echo "=============================="
echo "      INSTALL UNSHc         "
echo "=============================="
# script unshc
cd
wget -q -O /usr/bin/bongkar $source/unshc.sh
chmod +x /usr/bin/bongkar
# install webmin
echo -e "\e[40;38;5;238 " 
echo "=============================="
echo "        INSTALL BADVPN       "
echo "=============================="
cd
#wget -O webmin-current.deb http://prdownloads.sourceforge.net/webadmin/webmin_1.760_all.deb
wget -O webmin-current.deb $source/webmin-current.deb
dpkg -i --force-all webmin-current.deb
apt-get -y -f install;
#sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm -f /root/webmin-current.deb
apt-get -y --force-yes -f install libxml-parser-perl
service webmin restart
service vnstat restart
echo -e "\e[40;38;5;101m " 
echo "=============================="
echo "       INSTALL PPTP       "
echo "=============================="
# install pptp vpn
wget -O /root/pptp.sh $source/pptp.sh
chmod +x pptp.sh
./pptp.sh
echo -e "\e[40;38;5;28m " 
echo "=============================="
echo "        INSTALL MENJ       "
echo "=============================="
# download script
cd
wget -O /usr/bin/motd $source/motd
wget -O /usr/bin/benchmark $source/benchmark.sh
wget -O /usr/bin/speedtest $source/speedtest_cli.py
wget -O /usr/bin/ps-mem $source/ps_mem.py
wget -O /usr/bin/dropmon $source/dropmon.sh
wget -O /usr/bin/menu $source/menu.sh
wget -O /usr/bin/user-active-list $source/user-active-list.sh
wget -O /usr/bin/user-add $source/user-add.sh
wget -O /usr/bin/user-add-pptp $source/user-add-pptp.sh
wget -O /usr/bin/user-del $source/user-del.sh
wget -O /usr/bin/disable-user-expire $source/disable-user-expire.sh
wget -O /usr/bin/delete-user-expire $source/delete-user-expire.sh
wget -O /usr/bin/banned-user $source/banned-user.sh
wget -O /usr/bin/unbanned-user $source/unbanned-user.sh
wget -O /usr/bin/user-expire-list $source/user-expire-list.sh
wget -O /usr/bin/user-gen $source/user-gen.sh
wget -O /usr/bin/userlimit.sh $source/userlimit.sh
wget -O /usr/bin/userlimitssh.sh $source/userlimitssh.sh
wget -O /usr/bin/user-list $source/user-list.sh
wget -O /usr/bin/user-login $source/user-login.sh
wget -O /usr/bin/user-pass $source/user-pass.sh
wget -O /usr/bin/user-renew $source/user-renew.sh
wget -O /usr/bin/clearcache.sh $source/clearcache.sh
wget -O /usr/bin/bannermenu $source/bannermenu
cd

#rm -rf /etc/cron.weekly/
#rm -rf /etc/cron.hourly/
#rm -rf /etc/cron.monthly/
rm -rf /etc/cron.daily/
wget -O /root/passwd $source/passwd.sh
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
# swap ram
dd if=/dev/zero of=/swapfile bs=2048 count=2048k
# buat swap
mkswap /swapfile
# jalan swapfile
swapon /swapfile
#auto star saat reboot
wget $source/fstab
mv ./fstab /etc/fstab
chmod 644 /etc/fstab
sysctl vm.swappiness=10
#permission swapfile
chown root:root /swapfile 
chmod 0600 /swapfile
cd
echo -e "\e[40;38;5;101m " 
echo "=============================="
echo "     INSTA SSL / PORT 443      "
echo "=============================="
# install openvpn
wget $source/openvpn.sh && chmod +x openvpn.sh && ./openvpn.sh
# install ssl
apt-get update
apt-get upgrade
apt-get install stunnel4
wget -O /etc/stunnel/stunnel.conf $source/stunnel.conf
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

# Finishing
wget -O /etc/vpnfix.sh $source/vpnfix.sh
chmod 777 /etc/vpnfix.sh
sed -i 's/exit 0//g' /etc/rc.local
echo "" >> /etc/rc.local
echo "bash /etc/vpnfix.sh" >> /etc/rc.local
echo "$ screen badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &" >> /etc/rc.local
echo "nohup ./cron.sh &" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local
echo -e "\e[40;38;5;202m " 
echo "=============================="
echo "   RESTART ALL SERVICE    "
echo "=============================="
# finishing
chown -R www-data:www-data /home/vps/public_html
service cron restart
service nginx start
service php5-fpm start
service vnstat restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
service webmin restart
cd
rm -f /root/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile
# info
clear
echo "################################################################################" | lolcat
echo "#                                                                              #" | lolcat
echo "#      SSSSSSSSSSSSSSSSS  sssssssssssssssss  HHHHHHHHH        HHHHHHHHH        #" | lolcat
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHH        HHHHHHHHH        #" | lolcat
echo "#      SSSSSS             SSSSSS             HHHHHHHHH        HHHHHHHHH        #" | lolcat
echo "#      SSSSSS             SSSSSS             HHHHHHHHH        HHHHHHHHH        #" | lolcat
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHHHHHHHHHHHHHHHHHHH        #" | lolcat
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHHHHHHHHHHHHHHHHHHH        #" | lolcat
echo "#                 SSSSSS             SSSSSS  HHHHHHHHH        HHHHHHHHH        #" | lolcat
echo "#                 SSSSSS             SSSSSS  HHHHHHHHH        HHHHHHHHH        #" | lolcat
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHH        HHHHHHHHH        #" | lolcat
echo "#      SSSSSSSSSSSSSSSSS  SSSSSSSSSSSSSSSSS  HHHHHHHHH        HHHHHHHHH        #" | lolcat
echo "#------------------------------------------------------------------------------#" | lolcat
echo "#          SELAMAT DATANG DI SCRIPT AUTO SETUP VPS BY VPSPROJECT.              #" | lolcat
echo "#                       SCRIPT VERSION V2.0 FOR DEBIAN 7-8-9                   #" | lolcat
echo "#                               SEMOGA BERMANFAAT                              #" | lolcat
echo "#------------------------------------------------------------------------------#" | lolcat
echo "################################################################################" | lolcat
echo "============================================================" | tee -a log-install.txt| lolcat
echo " FINSIH AND THANK YOU / Please Restart You VPS     "| tee -a log-install.txt| lolcat
echo "============================================================" | tee -a log-install.txt| lolcat
echo "Service :" | tee -a log-install.txt | lolcat
echo "---------" | tee -a log-install.txt | lolcat
echo "OpenSSH  : 22, 143" | tee -a log-install.txt | lolcat
echo "Dropbear : 442 ,109,442" | tee -a log-install.txt | lolcat
echo "  SSL    : 443, 80" | tee -a log-install.txt | lolcat
echo "Squid3   : 8080 limit to IP $MYIP" | tee -a log-install.txt | lolcat
#echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:81/client.ovpn)" | tee -a log-install.txt | lolcat
echo "badvpn   : badvpn-udpgw port 7300" | tee -a log-install.txt | lolcat
echo "PPTP VPN : TCP 1723" | tee -a log-install.txt | lolcat
echo "nginx    : 81" | tee -a log-install.txt | lolcat
echo "" | tee -a log-install.txt | lolcat
echo "Tools :" | tee -a log-install.txt | lolcat
echo "axel, bmon, htop, iftop, mtr, rkhunter, nethogs: nethogs $ether" | tee -a log-install.txt | lolcat
echo "Script :" | tee -a log-install.txt | lolcat
echo "--------" | tee -a log-install.txt | lolcat
echo "" | tee -a log-install.txt
echo "Fitur lain :" | tee -a log-install.txt | lolcat
echo "------------" | tee -a log-install.txt | lolcat
echo "Webmin         : http://$MYIP:10000/" | tee -a log-install.txt | lolcat
echo "vnstat         : http://$MYIP:81/vnstat/ [Cek Bandwith]" | tee -a log-install.txt | lolcat
echo "MRTG           : http://$MYIP:81/mrtg/" | tee -a log-install.txt | lolcat
echo "Timezone       : Asia/Jakarta " | tee -a log-install.txt | lolcat
echo "Fail2Ban       : [on]" | tee -a log-install.txt | lolcat
echo "DDoS Deflate.  : [on]" | tee -a log-install.txt | lolcat
echo "Block Torrent  : [off]" | tee -a log-install.txt | lolcat
echo "IPv6           : [off]" | tee -a log-install.txt | lolcat
echo "Auto Lock User Expire tiap jam 00:00" | tee -a log-install.txt | lolcat
echo "Auto Reboot tiap jam 00:00 dan jam 12:00" | tee -a log-install.txt | lolcat
echo "Credit to all developers script, VpsProject" | tee -a log-install.txt | lolcat
echo "THANK YOU FOR CHOICE US!!" | tee -a log-install.txt | lolcat
echo "" | tee -a log-install.txt | lolcat
echo " !!! SILAHKAN REBOOT VPS ANDA !!!" | tee -a log-install.txt | lolcat
echo "=======================================================" | tee -a log-install.txt | lolcat
cd ~/
rm /root/1.sh
