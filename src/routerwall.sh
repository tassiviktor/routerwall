#!/bin/bash
### BEGIN INIT INFO
# Provides:          routerwall
# Required-Start:    $network
# Required-Stop:     
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Example initscript
# Description:       This file should be used to construct scripts to be
#                    placed in /etc/init.d.
### END INIT INFO

####################################
# RouterWall 1.0                   #
# (C) 2015 Viktor Tassi            #
####################################

# Interfaces

# External interfaces The first one will be set as default gateway.
# The second one will be configured in a secondary routing table
EXTERNAL_IFS="ppp0 ppp1"
INTERNAL_IFS="eth0 eth3 eth4"

#Trusted interface skips all rules
TRUSTED_IFS="eth0"

#NETWORKS

#Internal networks and masq' rules. Format: network,internal_interface,external_interface,internal_network_gateway
# Example: FWCONFIG="192.168.0.0/24,eth3,ppp0,192.168.0.1 192.168.1.0/24,eth4,ppp1,192.168.1.1 192.168.2.0/24,eth0,ppp1,192.168.2.1"
FWCONFIG=""

#Allowed external services on firewall
ALLOW_EXTERNAL_TCP=""
ALLOW_EXTERNAL_UDP=""

#Allowed internal services on firewall
ALLOW_INTERNAL_TCP=""
ALLOW_INTERNAL_UDP=""

#Port forwarding from external interface to local computer at specified IP:port
# In order: external port, protocol, external if,local ip, local port
#Example: PORTFW="33,tcp,ppp0,192.168.0.2,22 3336,tcp,ppp0,192.168.0.4,3306"
PORTFW=""

#Packet forwarding between networks
#Example: LANFW="192.168.0.0/24,192.168.1.220,81,tcp 192.168.0.0/24,192.168.1.220,34567,tcp 192.168.0.0/24,192.168.1.220,34599,tcp"
LANFW=""

#Other settings
ENABLE_PING_FW="yes"
ENABLE_XLAN_PING="yes"

# Enable mss clamping for PPP/DSL
CLAMPMSS="yes"

## Internal variables. Do NOT modify unless you really need

#Routing table number starting value
RT_SVAL=2
#Routing table name prefix
RT_NPREFIX="routerwall_"
#Routing rule prio starting value
RR_PSVAL=1000

#iptables location
IPT="/sbin/iptables"
IFC="/sbin/ifconfig"

### END OF CONFIG
### NOTHING TO EDIT BELOW THIS LINE! ###########################################

function bjoin { local IFS="$1"; shift; echo "$*"; }

function valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

function if_exists(){
	HAVEIF=`grep "$1" /proc/net/dev`
	if [ -z "$HAVEIF" ];then
		return 1;
	fi;
	return 0;
}

function ext_ip(){
	echo `$IFC $1 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'`
}

function cleanup_routes(){

	for i in $EXTERNAL_IFS; do
		# is interface exists?
		HAVEIF=`grep "${i}" /proc/net/dev`
		if [ -z "$HAVEIF" ];then
			continue
		fi;

		#Get external IP
		PPPIP=$(ext_ip $i);
	
		if ! valid_ip $PPPIP; then
			continue
		fi;
	
		for x in `ip rule list | grep -oE ${PPPIP}` ;do
			ip rule del from ${PPPIP}
		done
	done;

	for j in $FWCONFIG; do
		arr=($(echo $j | tr "," " "))
		
		for x in `ip rule list | grep -oE ${arr[0]}` ;do
			ip rule del from ${arr[0]}
		done
	done;

	# Cleanup table list
	TABLES=`cat /etc/iproute2/rt_tables | grep -oE ${RT_NPREFIX}[a-z0-9\_]*`
	for i in $TABLES;do
		ip route del table ${i}
	done;
	sed -i'' '/routerwall_/d' /etc/iproute2/rt_tables
}


# Allow trusted interfaces
function allow_trusted(){
	for i in $TRUSTED_IFS; do
		echo -n "Enabling trusted interface: ${TRUSTED_IFS} ..."
		$IPT -A INPUT -i ${i} -j ACCEPT
		$IPT -A OUTPUT -o ${i} -j ACCEPT
		echo "[ok]"
	done
}

init_firewall(){
	echo -n "Initializing Routerwall ..."

	#preparation
	modprobe nf_conntrack
	modprobe nf_conntrack_ftp
	modprobe xt_conntrack
	modprobe xt_LOG
	modprobe xt_state
	modprobe ip_nat_ftp
	modprobe ip_tables
	modprobe iptable_nat
	modprobe ipt_MASQUERADE

	echo "1" > /proc/sys/net/ipv4/ip_forward
	echo 2 > /proc/sys/net/ipv4/ip_dynaddr
	if [ -e /proc/sys/net/ipv4/conf/all/proxy_arp ]; then
  		for f in /proc/sys/net/ipv4/conf/*/proxy_arp; do
			echo 0 > $f
		done
	fi
	echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
	if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then
		for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
			echo 1 > $f
		done
	fi

	echo 1 > /proc/sys/net/ipv4/tcp_syncookies
	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
	echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all
	echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses


    # Log packets with impossible addresses.
    for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done

    # Don't accept or send ICMP redirects.
    for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done
    for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done

    # Don't accept source routed packets.
    # for i in /proc/sys/net/ipv4/conf/*/accept_source_route; do echo 0 > $i; done

    # Disable proxy_arp.
    for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > $i; done

    # Enable secure redirects, i.e. only accept ICMP redirects for gateways
    # Helps against MITM attacks.
    for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > $i; done

    # Disable bootp_relay
    for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do echo 0 > $i; done

	echo 1 > /proc/sys/net/ipv4/tcp_mtu_probing

	$IPT -F
	$IPT -X
	$IPT -Z
	$IPT -t nat -F

	$IPT -P INPUT DROP
	$IPT -P OUTPUT DROP
	$IPT -P FORWARD DROP

	# Allow local connections
	$IPT -A INPUT  -i lo -j ACCEPT
	$IPT -A OUTPUT -o lo -j ACCEPT
	
	NUL=`allow_trusted`

	# accept established sessions
    $IPT -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT 
    $IPT -A OUTPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT 
    $IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
	echo "[ok]"
}

stop_firewall() {
	echo -n "Stopping Routerwall ..."
	cleanup_routes
	if [ -f /proc/net/ip_tables_names ]; then
		chains=`cat /proc/net/ip_tables_names`
	    for i in $chains; do
    	  $IPT -t $i -F
    	  $IPT -t $i -X
    	  $IPT -t $i -Z
    	done
	fi
    $IPT -P INPUT DROP
    $IPT -P OUTPUT DROP
    $IPT -P FORWARD DROP
	echo "[ok]"
    allow_trusted
  }

start_firewall(){
	echo -n "Starting Routerwall ..."

    #Portscan block
    #$IPT -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
    #DDOS - Connection-flood block
    #$IPT -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 50/second --limit-burst 50 -j ACCEPT

        #SYN flood attack
        $IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
        #NULL packet block
        $IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
        #SYN CHECK
        $IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
        #TCP-FIN scan blokkolása (csak FIN csomagok)
        $IPT -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN -j DROP
        #TCP-ACK scan blokkolása (csak ACK csomagok)
        $IPT -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH ACK -j DROP
        #Block "Karácsonyfa" TCP-XMAS scan blokkoása (csomagok FIN, URG, PSH jelzővel)
        $IPT -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN,URG,PSH -j DROP
        #DOS - Teardrop blokkolása
        $IPT -A INPUT -p UDP -f -j DROP
        #DDOS - UDP-flood (Pepsi) blokkolás
        $IPT -A INPUT -p UDP --dport 7 -j DROP
        $IPT -A INPUT -p UDP --dport 19 -j DROP
        #DDOS - Jolt blokkolás
	$IPT -A INPUT -p ICMP -f -j DROP



	## Allow ports on internal interfaces
	for i in $INTERNAL_IFS; do
		for j in $ALLOW_INTERNAL_TCP; do
			$IPT -A INPUT -i ${i} -p tcp --dport ${j} -m state --state NEW -j ACCEPT
		done
		for j in $ALLOW_INTERNAL_UDP; do
			$IPT -A INPUT -i ${i} -p udp --dport ${j} -m state --state NEW -j ACCEPT
		done
		$IPT -A OUTPUT -o ${i} -j ACCEPT
	done

	## Allow ports on external interfaces
	for i in $EXTERNAL_IFS; do
		for j in $ALLOW_EXTERNAL_TCP; do
			$IPT -A INPUT -i ${i} -p tcp --dport ${j} -m state --state NEW -j ACCEPT
		done
		for j in $ALLOW_EXTERNAL_UDP; do
			$IPT -A INPUT -i ${i} -p udp --dport ${j} -m state --state NEW -j ACCEPT
		done
		$IPT -A OUTPUT -o ${i} -j ACCEPT

	        #Set up masq to all output interface. Route table will decide
		for k in $FWCONFIG; do
		    arr=($(echo $k | tr "," " "))
		    $IPT -t nat -A POSTROUTING -o ${i} -s ${arr[0]} -j MASQUERADE
		    $IPT -A FORWARD -o ${i} -s ${arr[0]} -j ACCEPT
		done
	done

	#Port forwarding
	for j in $PORTFW; do
		arr=($(echo $j | tr "," " "))
		$IPT -t nat -A PREROUTING -i ${arr[2]} -p ${arr[1]} --dport ${arr[0]} -j DNAT --to-destination ${arr[3]}:${arr[4]}
		$IPT -A FORWARD -i ${arr[2]} -d ${arr[3]} -j ACCEPT
	done

	#LAN port forwarding
	for j in $LANFW; do
	    arr=($(echo $j | tr "," " "))
	    $IPT -A FORWARD -p ${arr[3]} -s ${arr[0]} -d ${arr[1]} --dport ${arr[2]} -j ACCEPT
            $IPT -A FORWARD -p ${arr[3]} -d ${arr[0]} -s ${arr[1]} --sport ${arr[2]} -j ACCEPT
	done



	if [ $ENABLE_PING_FW == "yes" ]; then
		#DOS - Ping of Death blokkolása A halál pingje:
		$IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s -j ACCEPT
		#$IPT -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
		$IPT -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
	else
		$IPT -A INPUT -p icmp --icmp-type echo-request -j DROP
		$IPT -A OUTPUT -p icmp --icmp-type echo-reply -j DROP
	fi;

    if [ $ENABLE_XLAN_PING == "yes" ]; then
	LANLIST=()
	for k in $FWCONFIG; do
	    arr=($(echo $k | tr "," " "))
	    LANLIST+=("${arr[0]}")
	done
	echo ${LANLIST[@]}
	LANLIST=`bjoin , ${LANLIST[@]}`
	$IPT -A FORWARD -p icmp --icmp-type echo-request -s $LANLIST -d $LANLIST -j ACCEPT
	$IPT -A FORWARD -p icmp --icmp-type echo-reply -s $LANLIST -d $LANLIST -j ACCEPT
    fi


	if [ $CLAMPMSS == "yes" ]; then
	        #$IPT -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
		#$IPT -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1452
		$IPT -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	fi

	#Allow all other ICMP
	$IPT -A INPUT -p icmp -j ACCEPT
	$IPT -A OUTPUT -p icmp -j ACCEPT

	echo "[ok]"

    read -a EXTIF <<< "$EXTERNAL_IFS"
	if [ ${#EXTIF[@]} -gt 1 ];then

		echo "Multiple external interfaces detected. Setting up advanced routing ...";

		#Removing first interface (default) from list
		EXTIF=(${EXTIF[@]:1})

		cleanup_routes

		TABLECOUNTER=$RT_SVAL;
		RULECOUNTER=$RR_PSVAL;
		for i in $EXTIF; do

			# is interface exists?
			if ! if_exists $i ;then
				echo "Interface ${i} not working. Skipping ..."
				continue
			fi;

			#Get external IP			
			PPPIP=$(ext_ip $i);

			if ! valid_ip $PPPIP; then
				echo "Interface ${i} does not have valid IP or not available. Skipping ..."
				continue
			fi;

			#All ok. Have interface, have public IP. Make the work.
			#Generate table name
			INTCOUNT=0
			for j in $FWCONFIG; do
				arr=($(echo $j | tr "," " "))

				if [ "${arr[2]}" == "${i}" ]; then

					if ! valid_ip ${arr[3]}; then
						echo "Interface ${i} does not have valid gateway IP. Skipping ..."
						continue
					fi;

					#Generate unique tablename
					TABLENAME="${RT_NPREFIX}${i}_${INTCOUNT}"

					HAVETABLE=`grep "${TABLENAME}" /etc/iproute2/rt_tables`
					if [ -z "$HAVETABLE" ];then
						echo "${TABLECOUNTER} ${TABLENAME}" >> /etc/iproute2/rt_tables
					fi;

					if [ -z `ip route list table ${TABLENAME} | grep default` ]; then
						ip route add default via $PPPIP dev ${i} table ${TABLENAME}
					fi

					#We do not want to overwrite original table for reasons
					ip route add ${arr[0]} dev ${arr[1]} src ${arr[3]} table ${TABLENAME} 2> /dev/null

					#Build all other network rule
					for x in $FWCONFIG; do
					    arrx=($(echo $x | tr "," " "))
					    if [ "${arr[0]}" != "${arrx[0]}" ]; then
						ip route add ${arrx[0]} dev ${arrx[1]} src ${arrx[3]} table ${TABLENAME} 2> /dev/null
					    fi
					done
					
					ip rule add from $PPPIP lookup ${TABLENAME} prio ${RULECOUNTER}
					ip rule add from ${arr[0]} lookup ${TABLENAME} prio $((RULECOUNTER - 1))

					RULECOUNTER=$((RULECOUNTER - 2))
					INTCOUNT=$((INTCOUNT + 1))

				fi;

				#Increment counter
				TABLECOUNTER=$((TABLECOUNTER + 1))
			done
		done
		echo "Advanced routing setup complete."
	fi;
}

case "$1" in
	start|restart|reload)
	    if ! if_exists ppp0; then
	    sleep 9
	    fi
	    init_firewall
	    start_firewall
	    ;;
	stop)
	    stop_firewall
	    ;;
	*)
	    echo "Usage: $0 {start|stop|restart|reload}"
	    exit 1
	    ;;
esac
exit 0

