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
	clear
	echo "Mask debug-shell"
	sleep 2
	systemctl mask debug-shell.service
	systemctl stop debug-shell.service
	clear
	echo "Restrict SU"
	sleep 2
	echo "auth required pam_wheel.so" > /etc/pam.d/su
	clear
	echo "other lol"
	usermod -a /sbin/nologin root
	systemctl mask ctrl-alt-del.target
	sed -i 's/^#CtrlAltBurstAction=.*/CtrlAltBurstAction=none/' "/etc/systemd/system.conf"
	sleep 1
	clear
	#cCRON
	echo "CRON CRON"
	read -p "only root allowed ok? y/n " j
	if [[ $j == y ]]
	then
		sleep 1
		#remove bad
		rm /etc/cron.deny 2> /dev/null
		rm /etc/at.deny 2> /dev/null
		#make good
		echo 'root' > /etc/cron.allow
		echo 'root' > /etc/at.allow
		chown root:root /etc/cron.allow
		chmod og-rwx /etc/cron.allow
		chown root:root /etc/at.allow
		chmod og-rwx /etc/at.allow
		systemctl mask atd.service
		systemctl stop atd.service
		systemctl daemon-reload
	else
		echo "ok"
	fi
	clear 
	echo "audit time!"
	sleep 2
	sed -i 's/^action_mail_acct =.*/action_mail_acct = root/' "/etc/audit/auditd.conf"
	sed -i 's/^admin_space_left_action = .*/admin_space_left_action = halt/' "/etc/audit/auditd.conf"
	sed -i 's/^max_log_file_action =.*/max_log_file_action = keep_logs/' "/etc/audit/auditd.conf"
	sed -i 's/^space_left_action =.*/space_left_action = email/' "/etc/audit/auditd.conf"
	echo "may be no audit IDK MAN check it your self"
	sleep 4
	echo " Rhosts file"
	rm /etc/hosts.equiv
	sleep 2
	echo "postfix"
	postconf -e disable_vrfy_command=yes
	postconf -e smtpd_client_restrictions=permit_mynetworks,reject
	postconf -e inet_interfaces=loopback-only
	systemctl restart postfix.service
	clear
	sleep 2
	read -p "USB guard stuff" h
	apt-get install --no-install-recommends usbguard
	usbguard generate-policy > /tmp/rules.conf
	install -m 600 -o root -g root /tmp/rules.conf /etc/usbguard/rules.conf
	systemctl enable usbguard.service
	systemctl start usbguard.service
	sleep 2
	
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
	apt install rkhunter
	#auto update
	sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="yes"/' "/etc/rkhunter.conf"
	sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="yes"/' "/etc/rkhunter.conf"
	
	sleep 2
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
	#PASSWROD HISTORY
	sed -i '/the "Primary" block/apassword\trequired\t\t\tpam_pwhistory.so\tremember=5' "/etc/pam.d/common-password"
	#password pol
	cp pwquality.conf /etc/security/pwquality.conf
	chmod 0644 /etc/security/pwquality.conf
	
	echo "done" 
	sleep 2
	clear
	echo "User fix things"
	#get all users
	#HELPPppppppppppppp
	usrInfo=$( awk -F: '{ if ( $3 >= 1000 ) print $1 }' < /etc/passwd )
	
	for user in usrInfo
	do
	echo user
	done
	
	
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
	 systemctl restart systemd-sysctl
	 sleep 2
	 clear
	 echo "sys stuff done #chmod 0600 SYSCTL"
	 sleep 2
}
function sshd {
	#make dir
	#test in later phase
	ssh 127.0.0.1
	mkdir -p ~/ssh && chmod 700 ~/ssh
	touch ~/.ssh/config
	chmod 600 ~/.shh/config
  	sed -i '/HostKey.*ssh_host_dsa_key.*/d' "~/.shh/config"
	sed -i '/KeyRegenerationInterval.*/d' "~/.shh/config"
	sed -i '/ServerKeyBits.*/d' "~/.shh/config"
	sed -i '/UseLogin.*/d' "$SSHDFILE"
	sed -i 's/.*X11Forwarding.*/X11Forwarding no/' "$SSHDFILE"
	sed -i 's/.*LoginGraceTime.*/LoginGraceTime 20/' "$SSHDFILE"
	sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' "$SSHDFILE"
	sed -i 's/.*UsePrivilegeSeparation.*/UsePrivilegeSeparation sandbox/' "$SSHDFILE"
	sed -i 's/.*LogLevel.*/LogLevel VERBOSE/' "$SSHDFILE"
	sed -i 's/.*Banner.*/Banner \/etc\/issue.net/' "$SSHDFILE"
	sed -i 's/.*Subsystem.*sftp.*/Subsystem sftp internal-sftp/' "$SSHDFILE"
	sed -i 's/^#.*Compression.*/Compression no/' "$SSHDFILE"
	sed -i "s/.*Port.*/Port $SSH_PORT/" "$SSHDFILE"
}

function sudo_pro {
	echo "sudo saftey"
	if ! grep -qER '^Defaults.*use_pty$' /etc/sudo.conf; then
	  echo "Defaults use_pty" > /etc/sudoers.d/011_use_pty
	fi
	if ! grep -qER '^Defaults.*logfile' /etc/sudo.conf; then
	  echo 'Defaults logfile="/var/log/sudo.log"' > /etc/sudoers.d/012_logfile
	fi
	
	if ! grep -qER '^Defaults.*pwfeedback' /etc/sudo.conf; then
	  echo 'Defaults !pwfeedback' > /etc/sudoers.d/013_pwfeedback
	fi
	
	if ! grep -qER '^Defaults.*visiblepw' /etc/sudo.conf; then
	  echo 'Defaults !visiblepw' > /etc/sudoers.d/014_visiblepw
	fi
	
	if ! grep -qER '^Defaults.*passwd_timeout' /etc/sudo.conf; then
	  echo 'Defaults passwd_timeout=1' > /etc/sudoers.d/015_passwdtimeout
	fi	
	
	if ! grep -qER '^Defaults.*timestamp_timeout' /etc/sudo.conf; then
	    echo 'Defaults timestamp_timeout=5' > /etc/sudoers.d/016_timestamptimeout
	fi
	find /etc/sudoers.d/ -type f -name '[0-9]*' -exec chmod 0440 {} \;
	
	if ! grep -qER '^auth required pam_wheel.so' /etc/pam.d/su; then
	  echo "auth required pam_wheel.so use_uid group=sudo" >> /etc/pam.d/su
	fi
	sudo -ll > sudoll.log
}
function psat {
	echo "psad stuff   pen detection =)"
	apt install psad
	read -p "enter "
	sed -i "s/EMAIL_ADDRESSES             root@localhost;/EMAIL_ADDRESSES             wesleyhuhn@fisdk12.org;/" "/etc/psad/psad.conf"
	sed -i "s/HOSTNAME                    _CHANGEME_;/HOSTNAME                    $(hostname --fqdn);/" "/etc/psad/psad.conf"
	sed -i 's/ENABLE_AUTO_IDS             N;/ENABLE_AUTO_IDS               Y;/' "/etc/psad/psad.conf"
	sed -i 's/DANGER_LEVEL2               15;/DANGER_LEVEL2               15;/' "/etc/psad/psad.conf"
	sed -i 's/DANGER_LEVEL3               150;/DANGER_LEVEL3               150;/' "/etc/psad/psad.conf"
	sed -i 's/DANGER_LEVEL4               1500;/DANGER_LEVEL4               1500;/' "/etc/psad/psad.conf"
	sed -i 's/DANGER_LEVEL5               10000;/DANGER_LEVEL5               10000;/' "/etc/psad/psad.conf"
	sed -i 's/EMAIL_ALERT_DANGER_LEVEL    1;/EMAIL_ALERT_DANGER_LEVEL    5;/' "/etc/psad/psad.conf"
	sed -i 's/EMAIL_LIMIT                 0;/EMAIL_LIMIT                 5;/' "/etc/psad/psad.conf"
	sed -i 's/EXPECT_TCP_OPTIONS             *;/EXPECT_TCP_OPTIONS             Y;/'  "/etc/psad/psad.conf"
	sed -i 's/ENABLE_MAC_ADDR_REPORTING   N;/ENABLE_MAC_ADDR_REPORTING   Y;/' "/etc/psad/psad.conf"
	sed -i 's/AUTO_IDS_DANGER_LEVEL       5;/AUTO_IDS_DANGER_LEVEL       1;/' "/etc/psad/psad.conf"
	sed -i 's/ENABLE_AUTO_IDS_EMAILS      ;/ENABLE_AUTO_IDS_EMAILS      Y;/' "/etc/psad/psad.conf"
	sed -i 's/IGNORE_PORTS             *;/IGNORE_PORTS             NONE;/' "/etc/psad/psad.conf"
	sed -i 's/IPT_SYSLOG_FILE             \/var\/log\/messages;/IPT_SYSLOG_FILE             \/var\/log\/syslog;/' "/etc/psad/psad.conf"
	sed -i 's/SIG_UPDATE_URL              http:\/\/www.cipherdyne.org\/psad\/signatures;/SIG_UPDATE_URL              https:\/\/www.cipherdyne.org\/psad\/signatures;/'  "/etc/psad/psad.conf"
	
	psad --sig-update
	psad -H
	psad --fw-analyze
	
}
function start_path {
	echo "2 minute pause between"
	update_remove_packets
	read -t 120 -p "wait for points for not " 
	FTP
	read -p "wait for points for not " -t 120
	Samba
	read -p "wait for points for not " -t 120
	Tft
	read -p "wait for points for not " -t 120
	Vnc
	read -p "wait for points for not " -t 120
	remove_other
	read -p "wait for points for not " -t 120
	Mail_time
	read -p "wait for points for not " -t 120
	fireball
	read -p "wait for points for not " -t 120
	bad_pro
	read -p "wait for points for not " -t 120
	system
	read -p "wait for points for not " -t 120
	virus
	read -p "wait for points for not " -t 120
	login_security   # 17 not work passwd
	read -p "wait for points for not " -t 120
	sysctl_hard
	read -p "wait for points for not " -t 120
	sshd 
	sudo_pro

}
function menu {
	ans=""
	while [[ ans != 99 ]]
	do
	echo """
1. Update and remove packets
2. FTP remove or upgrade
3. Samba remove or upgrade
4. VNC remove or upgrade
5. Remove NetCat and other
6. Check for mail, remove 
7. Firewall, rules 
8. Bad removeing DCCP SCTP RDS TIPC and system
9. System harding
10. virus detect and Rkhunter
11. login security
12. sysctl harding
13. sshd
14. sudo
99.  QUIT
"""
	read -p "choice? " ans
	echo $ans
	if [[ $ans == 1 ]]; then
		update_remove_packets
	elif [[ $ans == 2 ]]; then
		FTP
	elif [[ $ans == 3 ]]; then
		Samba
	elif [[ $ans == 4 ]]; then
		Vnc
	elif [[ $ans == 5 ]]; then
		remove_other
	elif [[ $ans == 6 ]]; then
		Mail_time
	elif [[ $ans == 7 ]]; then
		fireball
	elif [[ $ans == 8 ]]; then
		bad_pro
	elif [[ $ans == 9 ]]; then
		system
	elif [[ $ans == 10 ]]; then
		virus
	elif [[ $ans == 11 ]]; then
		login_security
	elif [[ $ans == 12 ]]; then
		sysctl_hard
	elif [[ $ans == 13 ]]; then
		sshd
	elif [[ $ans == 14 ]]; then
		sudo_pro
	elif [[ $ans == 99 ]]; then
		break
	else
		echo "try again"
	fi
	
	done

}

#main
function main {
	echo """
1. First
2. Menu
"""
	read -p "choice" ch
	if [[ $ch == 1 ]]
	then
		start_path
	elif [[ $ch == 2 ]]
	then
		menu
	else
		echo "NO"
	fi
}	

#main

#update_remove_packets
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
#login_security   # 17 not work passwd
#sysctl_hard
#sshd          #need help ssh
#sudo_pro
psat


