#! /bin/bash


function update_remove_packets {
	#remove hacking tools
	apt remove john
	apt remove hydra
	apt remove nginx
	apt remove snmp
	apt remove xinetd
}

function FTP {  
	clear
	read -p "Remove FTP? y\n " a
	echo "$a"
	if [[ $a == y ]]; then
		echo "REMOVEING"
		PRO = 'pgrep vsftpd'
		sed -i 's/^/#/' /etc/vsftpd.conf
		kill $PRO
		apt remove ftp
		apt remove vsftpd
		sleep 2
	else
		echo "securing"
		sed -i 's/anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf
		sed -i 's/local_enable=.*/local_enable=YES/' /etc/vsftpd.conf
		sed -i 's/#write_enable=.*/write_enable=YES/' /etc/vsftpd.conf
		sed -i 's/#chroot_local_user=.*/chroot_local_user=YES/' /etc/vsftpd.conf
		sleep 2		
	fi
}
function Samba {
	clear
	read -p "Remove Samba? y\n " b
	echo "$b"
	if [[ $b == y ]]
	then
		echo "REMOVEING"
		apt remove samba
		sleep 2
	else
		echo "securing"
		sed -i '82 i\restrict anonymous =2' /etc/samba/smb.conf	
		sleep 2	
	fi
	
}
function Tft {
	clear
	read -p "Remove TFTPD? y\n " c
	echo "$c"
	if [[ $c == y ]]
	then
		echo "REMOVEING"
		apt remove TFTPD
		sleep 3
	else
		echo "ok"
		sleep 2
	fi

}
function Vnc {
	clear
	read -p "Remove VNC? y\n " d
	echo "$d"
	if [[ $d == y ]]
	then
		echo "REMOVEING"
		apt remove x11vnc
		sleep 3
		clear
		apt remove tightvncserver
		sleep 3
	else
		echo "ok"
		sleep 2
	fi

}
function NFT {
	clear
	read -p "Remove NFS? y\n " e
	echo "$e"
	if [[ $e == y ]]
	then
		echo "REMOVEING"
		apt remove nfs-kernel-server
		sleep 3
	else
		echo "ok"
		sleep 2
	fi
}
function remove_other {
	echo "Removing other stuff"
	sleep 2
	clear
	apt clean
	sleep 2
	clear
	apt remove qbittorrent 
	sleep 2
	clear
	apt remove utorrent 
	sleep 2
	clear
	apt remove ctorrent 
	sleep 2
	clear
	apt remove ktorrent 
	sleep 2
	clear
	apt remove rtorrent 
	sleep 2
	clear
	apt remove deluge 
	sleep 2
	clear
	apt remove transmission-gtk
	sleep 2
	clear
	apt remove transmission-common 
	sleep 2
	clear
	apt remove tixati 
	sleep 2
	clear
	apt remove frostwise 
	sleep 2
	clear
	apt remove vuze 
	sleep 2
	clear
	apt remove irssi
	sleep 2
	clear
	apt remove talk 
	sleep 2
	clear
	apt remove telnet
	sleep 2
	clear
	apt remove wireshark 
	sleep 2
	clear
	apt remove nmap 
	sleep 2
	clear
	apt remove john 
	sleep 2
	clear
	apt remove netcat 
	sleep 2
	clearapt remove netcat-openbsd 
	sleep 2
	clearapt remove netcat-traditional 
	sleep 2
	clearapt remove netcat-ubuntu 
	sleep 2
	clearapt remove netcat-minimal	 
	sleep 2
	clear
}
function Mail_time {
	apt list | grep -E 'postfix|sendmail'
	if [ $? -eq 0 ]
	then
		read -p "Mail servers remove? y/n " f
		if [ $f == y ]
		then
			apt remove postfix sendmail
			sleep 2
			clear
		else
			echo 'ok'
			sleep 2
			clear
		fi
		
	else
		echo "No mail"	
		sleep 2
		clear
	fi
}
# Firewall UFW
function fireball {
	apt install ufw
	wait $!
	echo "firewall installed"
	sleep 2
	
	read -p "Add rules? y/n " j
	if [ $j == y ]
	then
		# 3 rules
		ufw --force enable
	 	sed -i '/^COMMIT/i -A ufw-before-output -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT' /etc/ufw/before.rules
		sed -i '/^COMMIT/i -A ufw-before-output -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT' /etc/ufw/before.rules
		sed -i '/^COMMIT/i -A ufw6-before-output -p icmpv6 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT' /etc/ufw/before6.rules
		sed -i '/^COMMIT/i -A ufw6-before-output -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT' /etc/ufw/before6.rules
		sed -i '/^COMMIT/i -A FORWARD -j LOG --log-tcp-options --log-prefix "[UFW FORWARD]"' /etc/ufw/after.rules
		sed -i '/^COMMIT/i -A FORWARD -j LOG --log-tcp-options --log-prefix "[UFW FORWARD]"' /etc/ufw/after6.rules
		sed -i '/^COMMIT/i -A FORWARD -j LOG --log-tcp-options --log-prefix "[UFW FORWARD]"' /etc/ufw/before.rules
		sed -i '/^COMMIT/i -A FORWARD -j LOG --log-tcp-options --log-prefix "[UFW FORWARD]"' /etc/ufw/before6.rules
		sed -i '/^COMMIT/i -A INPUT -j LOG --log-tcp-options --log-prefix "[UFW INPUT]"' /etc/ufw/after.rules
		sed -i '/^COMMIT/i -A INPUT -j LOG --log-tcp-options --log-prefix "[UFW INPUT]"' /etc/ufw/after6.rules
		sed -i '/^COMMIT/i -A INPUT -j LOG --log-tcp-options --log-prefix "[UFW INPUT]"' /etc/ufw/before.rules
		sed -i '/^COMMIT/i -A INPUT -j LOG --log-tcp-options --log-prefix "[UFW INPUT]"' /etc/ufw/before6.rules
		
		
	    	ufw allow in on lo
	    	ufw allow out on lo
		#g
	    	ufw logging on
	    	ufw reload
	else
		clear
		echo "ok dont forget"
		sleep 3
		clear
	fi	
}
function virus {
	#Lynis
	apt-get install git
	clear
	echo "Lynis"
	sleep 1
	clear
	
	git clone https://github.com/CISOfy/lynis
	cd lynis || return
	sleep 2
	clear
	./lynis audit system
	read -p "enter" i
}
function bad_pro {
	echo "removing DCCP SCTP RDS TIPC protocols"
	sleep 2
	clear
	
	install dccp /bin/true
	install sctp /bin/true
	install rds /bin/true
	install tipc /bin/true
	sleep 2
	clear
	echo "Done pro, doing old files now"
	sleep 2
	clear
	install cramfs /bin/true
	install freevxfs /bin/true
	install jffs2 /bin/true
	install hfs /bin/true
	install hfsplus /bin/true
	install udf /bin/true
	install vfat /bin/true
}







#update_remove_packets
#FTP
#Samba
#Tft
#Vnc
#remove_other
#Mail_time
#fireball
#virus
bad_pro























