#! /bin/bash


function update_remove_packets {
	#remove hacking tools
	apt remove john
	apt remove hydra
	apt remove nginx
	apt remove snmp
	apt remove xinetd
	local PACKAGE_REMOVE
	PACKAGE_REMOVE= "apport autofs avahi beep git pastebinit popularity-contest rsh rsync talk telnet whoopsie xinetd yp-tools ypbind"
	
	for deb_remove in $PACKAGE_REMOVE; do
		apt-get remove "$deb_remove" -y
	done
	
	services="cups.service openvpn.service pure-ftpd.service rexec.service rsync.service rsyslog.service telnet.service vsftpd.service"
	for service in $services; do
		read -p "Would you like to disable $service? [y/n] >" yesNo
	        if [[ yesNo == "y" ]]  
	        then
	            systemctl disable $service 2> /dev/null 1>&2
	            echo "Script: [$SCRIPT_NUM] ::: Disabled $service"
		fi
	done
	sudo apt-get remove --reinstall firefox -y
}

function FTP {
	clear
	read -p "Remove FTP? y\n " a
	echo "$a"
	if [[ $a == y ]]
	then
		echo "REMOVEING"
		PRO = 'pgrep vsftpd'
		sed -i 's/^/#/' "/etc/vsftpd.conf"
		kill $PRO
		apt remove ftp
		apt remove vsftpd
		sleep 2
	else
		echo "securing"
		sed -i 's/anonymous_enable=.*/anonymous_enable=NO/' "/etc/vsftpd.conf"
		sed -i 's/local_enable=.*/local_enable=YES/' "/etc/vsftpd.conf"
		sed -i 's/#write_enable=.*/write_enable=YES/' "/etc/vsftpd.conf"
		sed -i 's/#chroot_local_user=.*/chroot_local_user=YES/' "/etc/vsftpd.conf"
		sleep 2	
		clear
		echo "vsftp to be as secure as possible"
		sed -i 's/anonymous_enable=.*/anonymous_enable=NO/' "/etc/vsftpd.conf"
	
	 	read -p "Would you like to have local users access the server? [y/n] >" l
	    	if [[ $l == y ]] 
	    	then
	        	sed -i 's/local_enable=.*/local_enable=YES/' "/etc/vsftpd.conf"
	    	fi
	
	    	read -p "Would you like to have uploads enabled? [y/n] >" up
	    	if [[ $up == y ]] 
	    	then
	        	sed -i 's/#write_enable=.*/write_enable=YES/' "/etc/vsftpd.conf"
	    	fi
			sed -i 's/#chroot_local_user=.*/chroot_local_user=YES/' "/etc/vsftpd.conf" 
	   	read -p "Would you like to have VSFTPD listen on IPV6 instead of IPV4? [y/n] >" ip
	    	if [[ $ip == y ]]
	    	then
	        	sed -i 's/#listen=*/listen=NO/' "/etc/vsftpd.conf"
	        	sed -i    's/listen_ipv6=*/listen_ipv6=YES/' "/etc/vsftpd.conf"
	    	else    
	        	sed -i 's/#listen=*/listen=YES' "/etc/vsftpd.conf"
	        	sed -i 's/listen_ipv6=*/listen_ipv6=NO/' "/etc/vsftpd.conf"
	    	fi
	    	sed -i 's/ssl_enable=*/ssl_enable=YES/' "/etc/vsftpd.conf"
	    	sed -i 's/xferlog_enable=*/xferlog_enable=YES/' "/etc/vsftpd.conf"
	    	sed -i 's/xferlog_std_format=*/xferlog_std_format=YES/' "/etc/vsftpd.conf"
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
	echo 'exit 0' > /etc/rc.local
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
	read -p "USB guard stuff... enter " h
	apt-get install --no-install-recommends usbguard
	usbguard generate-policy > /tmp/rules.conf
	install -m 600 -o root -g root /tmp/rules.conf /etc/usbguard/rules.conf
	systemctl enable usbguard.service
	systemctl start usbguard.service
	sleep 2
	echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
	#daily updates
	sed -i -e 's/APT::Periodic::Update-Package-Lists.*\+/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/10periodic
	sed -i -e 's/APT::Periodic::Download-Upgradeable-Packages.*\+/APT::Periodic::Download-Upgradeable-Packages "0";/' /etc/apt/apt.conf.d/10periodic
	
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
	apt install clamav
	apt-get install chkrootkit
	clamav
	freshclam
	clamscan -r --log=/var/log/xyzlog.log
	chkrootkit
	apt-get install clamtk -y
	read -p " enter"
}
function login_security {
	echo "login stuff"
	passwd -l root
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
	for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); 
	do  
		chmod -R 750 /home/${i} 
	done
	
	
}
function sysctl_hard {
	systemctl disable avahi-deamon

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
	sed -i '/UseLogin.*/d' "/etc/ssh/sshd_config"
	sed -i 's/.*X11Forwarding.*/X11Forwarding no/' "/etc/ssh/sshd_config"
	sed -i 's/.*LoginGraceTime.*/LoginGraceTime 20/' "/etc/ssh/sshd_config"
	sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' "/etc/ssh/sshd_config"
	sed -i 's/.*UsePrivilegeSeparation.*/UsePrivilegeSeparation sandbox/' "/etc/ssh/sshd_config"
	sed -i 's/.*LogLevel.*/LogLevel VERBOSE/' "/etc/ssh/sshd_config"
	sed -i 's/.*Banner.*/Banner \/etc\/issue.net/' "/etc/ssh/sshd_config"
	sed -i 's/.*Subsystem.*sftp.*/Subsystem sftp internal-sftp/' "/etc/ssh/sshd_config"
	sed -i 's/^#.*Compression.*/Compression no/' "/etc/ssh/sshd_config"
	sed -i "s/.*Port.*/Port $SSH_PORT/" "/etc/ssh/sshd_config"
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
	sleep 3
	clear
}
function users_file {
	#weird users
	echo "weird user"
	mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd
	echo "done"
	sleep 2
	echo "weird admin"
	mawk -F: '$1 == "sudo"' /etc/group
	sleep 2
	echo "empty passwords"
	mawk -F: '$2 == ""' /etc/passwd
	sleep 2
	echo "0 UID users"
	mawk -F: '$3 == 0 && $1 == "root"' /etc/passwd
	#fiels
	find / -xdev \( -nouser -o -nogroup \) -print
	read -p "enter to cont. "
	sleep 4
	clear
	typeArray=("*.sh" "*.shosts" "*shosts.equiv*" "*backdoor*.*" "bindshell.perl" "*.perl" "*.docx" "*.log" "*.rtf" "*.txt" "*.csv" "*.dat" "*.pptx" "*.xml" "*.m4a" "*.mp3" "*.mp4" "*.wav" "*.avi" "*.m4v" "*.mov" "*.svg" "*.jpg" "*.jpeg" "*.png" "*.xlsx" "*.db" "*.sql" "*.apk" "*.bat" "*.com" "*.exe" "*.wsf" "*.ps1" "*.zip" "*.rar" "*.torrent")
	for type in typeArray
	do
		find /home -type f -name "$type" -print >> badFiles
	done
	clear
	echo "sudo ls badFiles"
}
function ip_table {
		apt-get install -y iptables
		apt-get install -y iptables-persistent
		#Backup
		mkdir /iptables/
		touch /iptables/rules.v4.bak
		touch /iptables/rules.v6.bak
		iptables-save > /iptables/rules.v4.bak
		ip6tables-save > /iptables/rules.v6.bak
		#Clear out and default iptables
		iptables -t nat -F
		iptables -t mangle -F
		iptables -t nat -X
		iptables -t mangle -X
		iptables -F
		iptables -X
		iptables -P INPUT DROP
		iptables -P FORWARD DROP
		iptables -P OUTPUT ACCEPT
		ip6tables -t nat -F
		ip6tables -t mangle -F
		ip6tables -t nat -X
		ip6tables -t mangle -X
		ip6tables -F
		ip6tables -X
		ip6tables -P INPUT DROP
		ip6tables -P FORWARD DROP
		ip6tables -P OUTPUT DROP
		#Block Bad
		printf "Enter primary internet interface: eth0 lo ? "
		read interface
		#Blocks  going into the computer
		iptables -A INPUT -s 127.0.0.0/8 -i $interface -j DROP
		iptables -A INPUT -s 0.0.0.0/8 -j DROP
		iptables -A INPUT -s 100.64.0.0/10 -j DROP
		iptables -A INPUT -s 169.254.0.0/16 -j DROP
		iptables -A INPUT -s 192.0.0.0/24 -j DROP
		iptables -A INPUT -s 192.0.2.0/24 -j DROP
		iptables -A INPUT -s 198.18.0.0/15 -j DROP
		iptables -A INPUT -s 198.51.100.0/24 -j DROP
		iptables -A INPUT -s 203.0.113.0/24 -j DROP
		iptables -A INPUT -s 224.0.0.0/3 -j DROP
		#Blocks  from leaving the computer
		iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
		iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
		iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
		iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
		iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
		iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
		iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
		iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
		iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
		iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
		#Blocks outbound from source  - A bit overkill
		#iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
		#iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
		#iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
		#iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
		#iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
		#iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
		#iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
		#iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
		#iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
		#iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
		#Block receiving  intended for  - Super overkill
		iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
		iptables -A INPUT -d 0.0.0.0/8 -j DROP
		iptables -A INPUT -d 100.64.0.0/10 -j DROP
		iptables -A INPUT -d 169.254.0.0/16 -j DROP
		iptables -A INPUT -d 192.0.0.0/24 -j DROP
		iptables -A INPUT -d 192.0.2.0/24 -j DROP
		iptables -A INPUT -d 198.18.0.0/15 -j DROP
		iptables -A INPUT -d 198.51.100.0/24 -j DROP
		iptables -A INPUT -d 203.0.113.0/24 -j DROP
		iptables -A INPUT -d 224.0.0.0/3 -j DROP
		iptables -A INPUT -i lo -j ACCEPT
		#Least Strict Rules
		#iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
		#Strict Rules -- Only allow well known ports (1-1022)
		#iptables -A INPUT -p tcp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
		#iptables -A INPUT -p udp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
		#iptables -A OUTPUT -p tcp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		#iptables -A OUTPUT -p udp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		#iptables -A OUTPUT -o lo -j ACCEPT
		#iptables -P OUTPUT DROP
		#Very Strict Rules - Only allow HTTP/HTTPS, NTP and DNS
		#iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
		#iptables -A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
		#iptables -A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
		#iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
		#iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		#iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		#iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		#iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		#iptables -A OUTPUT -o lo -j ACCEPT
		#iptables -P OUTPUT DROP
		mkdir /etc/iptables/
		touch /etc/iptables/rules.v4
		touch /etc/iptables/rules.v6
		iptables-save > /etc/iptables/rules.v4
		ip6tables-save > /etc/iptables/rules.v6
}
function start_path {
	echo "2 minute pause between"
	update_remove_packets
	read -t 120 -p "wait for points for not " 
	FTP
	read -t 120 -p "wait for points for not " 
	Samba
	read -t 120 -p "wait for points for not " 
	Tft
	read -t 120 -p "wait for points for not " 
	Vnc
	read -t 120 -p "wait for points for not " 
	remove_other
	read -t 120 -p "wait for points for not " 
	Mail_time
	read -t 120 -p "wait for points for not " 
	fireball
	read -t 120 -p "wait for points for not " 
	bad_pro
	read -t 120 -p "wait for points for not " 
	system
	read -t 120 -p "wait for points for not " 
	virus
	read -t 120 -p "wait for points for not " 
	login_security 
	read -t 120 -p "wait for points for not " 
	sysctl_hard
	read -t 120 -p "wait for points for not " 
	sshd 
	read -t 120 -p "wait for points for not " 
	sudo_pro
	read -t 120 -p "wait for points for not " 
	psat
	read -t 120 -p "wait for points for not " 
	ip_table

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
8. Bad removeing DCCP SCTP RDS TIPC and system #
9. System harding
10. Virus detect and Rkhunter
11. Login security
12. Sysctl harding
13. Sshd #
14. Sudo
15. Psat
16. Users_file
17. IP_table
99. QUIT
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
		echo "No work"
		sleep 2
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
	elif [[ $ans == 15 ]]; then
		psat
	elif [[ $ans == 16 ]]; then
		users_file
	elif [[ $ans == 17 ]]; then
		clear
		echo "SORRY NO WORK 420"
	elif [[ $ans == 99 ]]; then
		break
	elif [[ $ans == 420 ]]; then
		echo "
		8. system but weird
		13. ssh but its a pain
		17. brecks internet "
		read -p "choice??? " sc
		
		if [[ $sc == 8 ]]; then
			bad_pro
		elif [[ $sc == 13 ]]; then
			sshd
		elif [[ $sc == 17 ]]; then
			ip_table
		else
			echo "NO BY"
			sleep 2
			clear
		fi
	elif [[ $ans == 1237 ]]; then
		echo "HI"
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
	if [[ $ch == 1 ]]; then
		read -p "dont" gggg
		read -p "dont" gggg
		start_path
	elif [[ $ch == 2 ]]
	then
		menu
	else
		echo "NO"
	fi
}	

main

#update_remove_packets
#FTP
#Samba
#Tft
#Vnc
#remove_other
#Mail_time
#fireball
#bad_pro #
#system
#virus
#login_security
#sysctl_hard
#sshd          #need help ssh
#sudo_pro
#psat
#users_file
#ip_table

#thsiu o os a vuudh fgowik n tehwdiow njd wD;WJKdwDWD wjkd W FWFELW;FKJLKJEFLK;WflkjwfjlkWFL;KJWFlkjWFLKJWflkjWL;KWflkjwFLKJWFwFLKWJfL;KWFJWL;KfjwFKL;JL;KECVJIOVJQLK;MCF;LJMFCKLWEJFCLJ
#QEGUHIOUHIUBHRIJKNGJNEWGKJNEWPOIGJEIOPG JNPIOEJOIPVJOQPDOPKOJK34IU89-7891435-9348UNV5JLJM3,4;DIU1345U9083U1953NDU1DM343490134J905V[34134V459VEQGEQ
#QGQFQFNP8WEF	UOIPFWE	WEF	WEF		WEFW	FNOWEFW	EX	RKODJL;DE	WL;CKC	IODCPODDOCJKcOPIDC[	EDCP'	CD;'C		CDLC	D	DCC	E;PCDE	KD	CEP'	DE	DCEK	ECD'P	CEDL	O	CEDMCDE	DEC'	CPOC		CDEP'	DD	ECCDE3KPMO
#thsiu o os a vuudh fgowik n tehwdiow njd wD;WJKdwDWD wjkd W FWFELW;FKJLKJEFLK;WflkjwfjlkWFL;KJWFlkjWFLKJWflkjWL;KWflkjwFLKJWFwFLKWJfL;KWFJWL;KfjwFKL;JL;KECVJIOVJQLK;MCF;LJMFCKLWEJFCLJ
#QEGUHIOUHIUBHRIJKNGJNEWGKJNEWPOIGJEIOPG JNPIOEJOIPVJOQPDOPKOJK34IU89-7891435-9348UNV5JLJM3,4;DIU1345U9083U1953NDU1DM343490134J905V[34134V459VEQGEQ
#QGQFQFNP8WEF	UOIPFWE	WEF	WEF		WEFW	FNOWEFW	EX	RKODJL;DE	WL;CKC	IODCPODDOCJKcOPIDC[	EDCP'	CD;'C		CDLC	D	DCC	E;PCDE	KD	CEP'	DE	DCEK	ECD'P	CEDL	O	CEDMCDE	DEC'	CPOC		CDEP'	DD	ECCDE3KPMO
#thsiu o os a vuudh fgowik n tehwdiow njd wD;WJKdwDWD wjkd W FWFELW;FKJLKJEFLK;WflkjwfjlkWFL;KJWFlkjWFLKJWflkjWL;KWflkjwFLKJWFwFLKWJfL;KWFJWL;KfjwFKL;JL;KECVJIOVJQLK;MCF;LJMFCKLWEJFCLJ
#QEGUHIOUHIUBHRIJKNGJNEWGKJNEWPOIGJEIOPG JNPIOEJOIPVJOQPDOPKOJK34IU89-7891435-9348UNV5JLJM3,4;DIU1345U9083U1953NDU1DM343490134J905V[34134V459VEQGEQ
#QGQFQFNP8WEF	UOIPFWE	WEF	WEF		WEFW	FNOWEFW	EX	RKODJL;DE	WL;CKC	IODCPODDOCJKcOPIDC[	EDCP'	CD;'C		CDLC	D	DCC	E;PCDE	KD	CEP'	DE	DCEK	ECD'P	CEDL	O	CEDMCDE	DEC'	CPOC		CDEP'	DD	ECCDE3KPMO
#thsiu o os a vuudh fgowik n tehwdiow njd wD;WJKdwDWD wjkd W FWFELW;FKJLKJEFLK;WflkjwfjlkWFL;KJWFlkjWFLKJWflkjWL;KWflkjwFLKJWFwFLKWJfL;KWFJWL;KfjwFKL;JL;KECVJIOVJQLK;MCF;LJMFCKLWEJFCLJ
#QEGUHIOUHIUBHRIJKNGJNEWGKJNEWPOIGJEIOPG JNPIOEJOIPVJOQPDOPKOJK34IU89-7891435-9348UNV5JLJM3,4;DIU1345U9083U1953NDU1DM343490134J905V[34134V459VEQGEQ
#QGQFQFNP8WEF	UOIPFWE	WEF	WEF		WEFW	FNOWEFW	EX	RKODJL;DE	WL;CKC	IODCPODDOCJKcOPIDC[	EDCP'	CD;'C		CDLC	D	DCC	E;PCDE	KD	CEP'	DE	DCEK	ECD'P	CEDL	O	CEDMCDE	DEC'	CPOC		CDEP'	DD	ECCDE3KPMO
#thsiu o os a vuudh fgowik n tehwdiow njd wD;WJKdwDWD wjkd W FWFELW;FKJLKJEFLK;WflkjwfjlkWFL;KJWFlkjWFLKJWflkjWL;KWflkjwFLKJWFwFLKWJfL;KWFJWL;KfjwFKL;JL;KECVJIOVJQLK;MCF;LJMFCKLWEJFCLJ
#QEGUHIOUHIUBHRIJKNGJNEWGKJNEWPOIGJEIOPG JNPIOEJOIPVJOQPDOPKOJK34IU89-7891435-9348UNV5JLJM3,4;DIU1345U9083U1953NDU1DM343490134J905V[34134V459VEQGEQ
#QGQFQFNP8WEF	UOIPFWE	WEF	WEF		WEFW	FNOWEFW	EX	RKODJL;DE	WL;CKC	IODCPODDOCJKcOPIDC[	EDCP'	CD;'C		CDLC	D	DCC	E;PCDE	KD	CEP'	DE	DCEK	ECD'P	CEDL	O	CEDMCDE	DEC'	CPOC		CDEP'	DD	ECCDE3KPMO
