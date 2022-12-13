#! /bin/bash


function update_remove_packets {
	#remove hacking tools
	apt remove john
	apt remove hydra
	apt remove nginx
	apt remove snmp
	apt remove xinetd
	local PACKAGE_REMOVE
	PACKAGE_REMOVE="apport* autofs avahi* beep git pastebinit popularity-contest rsh* rsync talk* telnet* tftp* whoopsie xinetd yp-tools ypbind"
	
	for deb_remove in $PACKAGE_REMOVE; do
		apt-get remove "$deb_remove" -y
	done
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
	
	sleep 2
	clear 
	echo "who knows if that worked check /dev/null"
	sleep 2
}
function system {
	sed -i 's/^#DumpCore=.*/DumpCore=no/' "/etc/systemd/system.conf"
	sed -i 's/^#CrashShell=.*/CrashShell=no/' "/etc/systemd/system.conf"
	sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "/etc/systemd/system.conf"
	sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1024/' "/etc/systemd/system.conf"
	sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=1024/' "/etc/systemd/system.conf"
	sleep 1
	sed -i 's/^#DefaultLimitCORE=.*/DefaultLimitCORE=0/' "$USERCONF"
	sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1024/' "$USERCONF"
	sed -i 's/^#DefaultLimitNPROC=.*/DefaultLimitNPROC=1024/' "$USERCONF"
	sleep 1
	clear
	echo "system hard"
	clear
	echo "hosts things"
	sleep 2	
	echo "sshd : ALL : ALLOW" >> /etc/hosts.allow
	echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
	echo "ALL: ALL" > /etc/hosts.deny
	chmod 644 /etc/hosts.allow
	chmod 644 /etc/hosts.deny
	
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
	#./lynis audit system
	read -p "enter" X
	clear
}
function login_security {
	echo "login stuff"

	sed -i 's/^.*LOG_OK_LOGINS.*/LOG_OK_LOGINS yes/' "/etc/login.defs"
	sed -i 's/^UMASK.*/UMASK 077/' "/etc/login.defs"
	sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' "/etc/login.defs"
	sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' "/etc/login.defs"
	sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' "/etc/login.defs"
	sed -i 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' "/etc/login.defs"
	sed -i 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' "/etc/login.defs"
	sed -i 's/^#.*SHA_CRYPT_MIN_ROUNDS .*/SHA_CRYPT_MIN_ROUNDS 10000/' "/etc/login.defs"
	sed -i 's/^#.*SHA_CRYPT_MAX_ROUNDS .*/SHA_CRYPT_MAX_ROUNDS 65536/' "/etc/login.defs"
	echo "done"
	sleep 2
	clear
}
function sysctl_hard {
	 sysctl -w dev.tty.ldisc_autoload=0
	 sysctl -w fs.protected_fifos=2
	 sysctl -w fs.protected_hardlinks=1
	 sysctl -w fs.protected_symlinks=1
	 sysctl -w fs.suid_dumpable=0
	 sysctl -w kernel.core_uses_pid=1
	 sysctl -w kernel.dmesg_restrict=1
	 sysctl -w kernel.kptr_restrict=2
	 sysctl -w kernel.panic=60
	 sysctl -w kernel.panic_on_oops=60
	 sysctl -w kernel.perf_event_paranoid=3
	 sysctl -w kernel.randomize_va_space=2
	 sysctl -w kernel.sysrq=0
	 sysctl -w kernel.unprivileged_bpf_disabled=1
	 sysctl -w kernel.yama.ptrace_scope=2
	 sysctl -w net.core.bpf_jit_harden=2
	 sysctl -w net.ipv4.conf.all.accept_redirects=0
	 sysctl -w net.ipv4.conf.all.accept_source_route=0
	 sysctl -w net.ipv4.conf.all.log_martians=1
	 sysctl -w net.ipv4.conf.all.rp_filter=1
	 sysctl -w net.ipv4.conf.all.secure_redirects=0
	 sysctl -w net.ipv4.conf.all.send_redirects=0
	 sysctl -w net.ipv4.conf.all.shared_media=0
	 sysctl -w net.ipv4.conf.default.accept_redirects=0
	 sysctl -w net.ipv4.conf.default.accept_source_route=0
	 sysctl -w net.ipv4.conf.default.log_martians=1
	 sysctl -w net.ipv4.conf.default.rp_filter=1
	 sysctl -w net.ipv4.conf.default.secure_redirects=0
	 sysctl -w net.ipv4.conf.default.send_redirects=0
	 sysctl -w net.ipv4.conf.default.shared_media=0
	 sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
	 sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
	 sysctl -w net.ipv4.ip_forward=0
	 sysctl -w net.ipv4.tcp_challenge_ack_limit=2147483647
	 sysctl -w net.ipv4.tcp_invalid_ratelimit=500
	 sysctl -w net.ipv4.tcp_max_syn_backlog=20480
	 sysctl -w net.ipv4.tcp_rfc1337=1
	 sysctl -w net.ipv4.tcp_syn_retries=5
	 sysctl -w net.ipv4.tcp_synack_retries=2
	 sysctl -w net.ipv4.tcp_syncookies=1
	 sysctl -w net.ipv6.conf.all.accept_ra=0
	 sysctl -w net.ipv6.conf.all.accept_redirects=0
	 sysctl -w net.ipv6.conf.all.accept_source_route=0
	 sysctl -w net.ipv6.conf.all.forwarding=0
	 sysctl -w net.ipv6.conf.all.use_tempaddr=2
	 sysctl -w net.ipv6.conf.default.accept_ra=0
	 sysctl -w net.ipv6.conf.default.accept_ra_defrtr=0
	 sysctl -w net.ipv6.conf.default.accept_ra_pinfo=0
	 sysctl -w net.ipv6.conf.default.accept_ra_rtr_pref=0
	 sysctl -w net.ipv6.conf.default.accept_redirects=0
	 sysctl -w net.ipv6.conf.default.accept_source_route=0
	 sysctl -w net.ipv6.conf.default.autoconf=0
	 sysctl -w net.ipv6.conf.default.dad_transmits=0
	 sysctl -w net.ipv6.conf.default.max_addresses=1
	 sysctl -w net.ipv6.conf.default.router_solicitations=0
	 sysctl -w net.ipv6.conf.default.use_tempaddr=2
	 sysctl -w net.ipv6.conf.eth0.accept_ra_rtr_pref=0
	 sysctl -w net.filter.nf_conntrack_max=2000000
	 sysctl -w net.filter.nf_conntrack_tcp_loose=0
	 sysctl -w kernel.panic=10
	 sysctl -w kernel.modules_disabled=1  
	 #chmod 0600 "$SYSCTL"
	 systemctl restart systemd-sysctl
	 sleep 2
	 clear
	 echo "sys stuff done"
	 sleep 2
}



update_remove_packets
#FTP
#Samba
#Tft
#Vnc
#remove_other
#Mail_time
#fireball
#bad_pro
#system
#virus
#login_security
#sysctl_hard






