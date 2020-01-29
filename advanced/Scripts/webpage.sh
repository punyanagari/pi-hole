#!/usr/bin/env bash
# shellcheck disable=SC1090

# Pi-hole: A black hole for Internet advertisements
# (c) 2017 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# Web interface settings
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

readonly setupVars="/etc/pihole/setupVars.conf"
readonly arahasya="/opt/pihole/arahasya/arahasya.conf"
readonly nord="/opt/pihole/arahasya/nord.conf"
readonly hostapd="/etc/hostapd/hostapd.conf"
readonly dnsmasqconfig="/etc/dnsmasq.d/01-pihole.conf"
readonly dhcpconfig="/etc/dnsmasq.d/02-pihole-dhcp.conf"
readonly FTLconf="/etc/pihole/pihole-FTL.conf"
# 03 -> wildcards
readonly dhcpstaticconfig="/etc/dnsmasq.d/04-pihole-static-dhcp.conf"
readonly PI_HOLE_BIN_DIR="/usr/local/bin"

coltable="/opt/pihole/COL_TABLE"
if [[ -f ${coltable} ]]; then
    source ${coltable}
fi

helpFunc() {
    echo "Usage: pihole -a [options]
Example: pihole -a -p password
Set options for the Admin Console

Options:
  -p, password        Set Admin Console password
  -c, celsius         Set Celsius as preferred temperature unit
  -f, fahrenheit      Set Fahrenheit as preferred temperature unit
  -k, kelvin          Set Kelvin as preferred temperature unit
  -r, hostrecord      Add a name to the DNS associated to an IPv4/IPv6 address
  -e, email           Set an administrative contact address for the Block Page
  -h, --help          Show this help dialog
  -i, interface       Specify dnsmasq's interface listening behavior
  -l, privacylevel    Set privacy level (0 = lowest, 4 = highest)"
    exit 0
}

add_setting() {
    echo "${1}=${2}" >> "${setupVars}"
}

delete_setting() {
    sed -i "/${1}/d" "${setupVars}"
}

change_setting() {
    delete_setting "${1}"
    add_setting "${1}" "${2}"
}

add_arahasya() {
    echo "${1}=${2}" >> "${arahasya}"
}

delete_arahasya() {
    sed -i "/${1}/d" "${arahasya}"
}

change_arahasya() {
    delete_arahasya "${1}"
    add_arahasya "${1}" "${2}"
}

add_nord() {
    echo "${1}=${2}" >> "${nord}"
}

delete_nord() {
    sed -i "/${1}/d" "${nord}"
}

change_nord() {
    delete_nord "${1}"
    add_nord "${1}" "${2}"
}
add_hostapd() {
    echo "${1}=${2}" >> "${hostapd}"
}

delete_hostapd() {
    sed -i "/${1}/d" "${hostapd}"
}

change_hostapd() {
    delete_hostapd "${1}"
    add_hostapd "${1}" "${2}"
}

addFTLsetting() {
    echo "${1}=${2}" >> "${FTLconf}"
}

deleteFTLsetting() {
    sed -i "/${1}/d" "${FTLconf}"
}

changeFTLsetting() {
    deleteFTLsetting "${1}"
    addFTLsetting "${1}" "${2}"
}

add_dnsmasq_setting() {
    if [[ "${2}" != "" ]]; then
        echo "${1}=${2}" >> "${dnsmasqconfig}"
    else
        echo "${1}" >> "${dnsmasqconfig}"
    fi
}

delete_dnsmasq_setting() {
    sed -i "/${1}/d" "${dnsmasqconfig}"
}

SetTemperatureUnit() {
    change_setting "TEMPERATUREUNIT" "${unit}"
    echo -e "  ${TICK} Set temperature unit to ${unit}"
}

HashPassword() {
    # Compute password hash twice to avoid rainbow table vulnerability
    return=$(echo -n ${1} | sha256sum | sed 's/\s.*$//')
    return=$(echo -n ${return} | sha256sum | sed 's/\s.*$//')
    echo ${return}
}

SetWebPassword() {

    if (( ${#args[2]} > 0 )) ; then
        readonly PASSWORD="${args[2]}"
        readonly CONFIRM="${PASSWORD}"
    else
        # Prevents a bug if the user presses Ctrl+C and it continues to hide the text typed.
        # So we reset the terminal via stty if the user does press Ctrl+C
        trap '{ echo -e "\nNo password will be set" ; stty sane ; exit 1; }' INT
        read -s -r -p "Enter New Password (Blank for no password): " PASSWORD
        echo ""

    if [ "${PASSWORD}" == "" ]; then
        change_setting "WEBPASSWORD" ""
        echo -e "  ${TICK} Password Removed"
        exit 0
    fi

    read -s -r -p "Confirm Password: " CONFIRM
    echo ""
    fi

    if [ "${PASSWORD}" == "${CONFIRM}" ] ; then
        # We do not wrap this in brackets, otherwise BASH will expand any appropriate syntax
        hash=$(HashPassword "$PASSWORD")
        # Save hash to file
        change_setting "WEBPASSWORD" "${hash}"
        echo -e "  ${TICK} New password set"
    else
        echo -e "  ${CROSS} Passwords don't match. Your password has not been changed"
        exit 1
    fi
}

ProcessDNSSettings() {
    source "${setupVars}"

    delete_dnsmasq_setting "server"

    COUNTER=1
    while [[ 1 ]]; do
        var=PIHOLE_DNS_${COUNTER}
        if [ -z "${!var}" ]; then
            break;
        fi
        add_dnsmasq_setting "server" "${!var}"
        let COUNTER=COUNTER+1
    done

    # The option LOCAL_DNS_PORT is deprecated
    # We apply it once more, and then convert it into the current format
    if [ ! -z "${LOCAL_DNS_PORT}" ]; then
        add_dnsmasq_setting "server" "127.0.0.1#${LOCAL_DNS_PORT}"
        add_setting "PIHOLE_DNS_${COUNTER}" "127.0.0.1#${LOCAL_DNS_PORT}"
        delete_setting "LOCAL_DNS_PORT"
    fi

    delete_dnsmasq_setting "domain-needed"

    if [[ "${DNS_FQDN_REQUIRED}" == true ]]; then
        add_dnsmasq_setting "domain-needed"
    fi

    delete_dnsmasq_setting "bogus-priv"

    if [[ "${DNS_BOGUS_PRIV}" == true ]]; then
        add_dnsmasq_setting "bogus-priv"
    fi

    delete_dnsmasq_setting "dnssec"
    delete_dnsmasq_setting "trust-anchor="

    if [[ "${DNSSEC}" == true ]]; then
        echo "dnssec
trust-anchor=.,19036,8,2,49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
" >> "${dnsmasqconfig}"
    fi

    delete_dnsmasq_setting "host-record"

    if [ ! -z "${HOSTRECORD}" ]; then
        add_dnsmasq_setting "host-record" "${HOSTRECORD}"
    fi

    # Setup interface listening behavior of dnsmasq
    delete_dnsmasq_setting "interface"
    delete_dnsmasq_setting "local-service"

    if [[ "${DNSMASQ_LISTENING}" == "all" ]]; then
        # Listen on all interfaces, permit all origins
        add_dnsmasq_setting "except-interface" "nonexisting"
    elif [[ "${DNSMASQ_LISTENING}" == "local" ]]; then
        # Listen only on all interfaces, but only local subnets
        add_dnsmasq_setting "local-service"
    else
        # Listen only on one interface
        # Use eth0 as fallback interface if interface is missing in setupVars.conf
        if [ -z "${PIHOLE_INTERFACE}" ]; then
            PIHOLE_INTERFACE="eth0"
        fi

        add_dnsmasq_setting "interface" "${PIHOLE_INTERFACE}"
    fi

    if [[ "${CONDITIONAL_FORWARDING}" == true ]]; then
        add_dnsmasq_setting "server=/${CONDITIONAL_FORWARDING_DOMAIN}/${CONDITIONAL_FORWARDING_IP}"
        add_dnsmasq_setting "server=/${CONDITIONAL_FORWARDING_REVERSE}/${CONDITIONAL_FORWARDING_IP}"
    fi
}

SetDNSServers() {
    # Save setting to file
    delete_setting "PIHOLE_DNS"
    IFS=',' read -r -a array <<< "${args[2]}"
    for index in "${!array[@]}"
    do
        add_setting "PIHOLE_DNS_$((index+1))" "${array[index]}"
    done

    if [[ "${args[3]}" == "domain-needed" ]]; then
        change_setting "DNS_FQDN_REQUIRED" "true"
    else
        change_setting "DNS_FQDN_REQUIRED" "false"
    fi

    if [[ "${args[4]}" == "bogus-priv" ]]; then
        change_setting "DNS_BOGUS_PRIV" "true"
    else
        change_setting "DNS_BOGUS_PRIV" "false"
    fi

    if [[ "${args[5]}" == "dnssec" ]]; then
        change_setting "DNSSEC" "true"
    else
        change_setting "DNSSEC" "false"
    fi

    if [[ "${args[6]}" == "conditional_forwarding" ]]; then
        change_setting "CONDITIONAL_FORWARDING" "true"
        change_setting "CONDITIONAL_FORWARDING_IP" "${args[7]}"
        change_setting "CONDITIONAL_FORWARDING_DOMAIN" "${args[8]}"
        change_setting "CONDITIONAL_FORWARDING_REVERSE" "${args[9]}"
    else
        change_setting "CONDITIONAL_FORWARDING" "false"
        delete_setting "CONDITIONAL_FORWARDING_IP"
        delete_setting "CONDITIONAL_FORWARDING_DOMAIN"
        delete_setting "CONDITIONAL_FORWARDING_REVERSE"
    fi

    ProcessDNSSettings

    # Restart dnsmasq to load new configuration
    RestartDNS
    if [[ "${PIHOLE_DNS_1}" == "127.0.0.1#4344" ]]; then
     	change_arahasya "DNS_CRYPT" "Enabled"
    else
	change_arahasya "DNS_CRYPT" "Disabled"
    fi
}
SetExcludeDomains() {
    change_setting "API_EXCLUDE_DOMAINS" "${args[2]}"
}

SetExcludeClients() {
    change_setting "API_EXCLUDE_CLIENTS" "${args[2]}"
}

Poweroff(){
    nohup bash -c "sleep 5; poweroff" &> /dev/null </dev/null &
}

Reboot() {
    nohup bash -c "sleep 5; reboot" &> /dev/null </dev/null &
}

RestartDNS() {
    "${PI_HOLE_BIN_DIR}"/pihole restartdns
}

SetQueryLogOptions() {
    change_setting "API_QUERY_LOG_SHOW" "${args[2]}"
}

ProcessDHCPSettings() {
    source "${setupVars}"

    if [[ "${DHCP_ACTIVE}" == "true" ]]; then
    interface="${PIHOLE_INTERFACE}"

    # Use eth0 as fallback interface
    if [ -z ${interface} ]; then
        interface="eth0"
    fi

    if [[ "${PIHOLE_DOMAIN}" == "" ]]; then
        PIHOLE_DOMAIN="lan"
        change_setting "PIHOLE_DOMAIN" "${PIHOLE_DOMAIN}"
    fi

    if [[ "${DHCP_LEASETIME}" == "0" ]]; then
        leasetime="infinite"
    elif [[ "${DHCP_LEASETIME}" == "" ]]; then
        leasetime="24"
        change_setting "DHCP_LEASETIME" "${leasetime}"
    elif [[ "${DHCP_LEASETIME}" == "24h" ]]; then
        #Installation is affected by known bug, introduced in a previous version.
        #This will automatically clean up setupVars.conf and remove the unnecessary "h"
        leasetime="24"
        change_setting "DHCP_LEASETIME" "${leasetime}"
    else
        leasetime="${DHCP_LEASETIME}h"
    fi

    # Write settings to file
    echo "###############################################################################
#  DHCP SERVER CONFIG FILE AUTOMATICALLY POPULATED BY PI-HOLE WEB INTERFACE.  #
#            ANY CHANGES MADE TO THIS FILE WILL BE LOST ON CHANGE             #
###############################################################################
dhcp-authoritative
dhcp-range=${DHCP_START},${DHCP_END},${leasetime}
dhcp-option=option:router,${DHCP_ROUTER}
dhcp-leasefile=/etc/pihole/dhcp.leases
#quiet-dhcp
" > "${dhcpconfig}"

    if [[ "${PIHOLE_DOMAIN}" != "none" ]]; then
        echo "domain=${PIHOLE_DOMAIN}" >> "${dhcpconfig}"
    fi

    # Sourced from setupVars
    # shellcheck disable=SC2154
    if [[ "${DHCP_rapid_commit}" == "true" ]]; then
        echo "dhcp-rapid-commit" >> "${dhcpconfig}"
    fi

    if [[ "${DHCP_IPv6}" == "true" ]]; then
        echo "#quiet-dhcp6
#enable-ra
dhcp-option=option6:dns-server,[::]
dhcp-range=::100,::1ff,constructor:${interface},ra-names,slaac,${leasetime}
ra-param=*,0,0
" >> "${dhcpconfig}"
    fi

    else
        if [[ -f "${dhcpconfig}" ]]; then
            rm "${dhcpconfig}" &> /dev/null
        fi
    fi
}

EnableDHCP() {
    change_setting "DHCP_ACTIVE" "true"
    change_setting "DHCP_START" "${args[2]}"
    change_setting "DHCP_END" "${args[3]}"
    change_setting "DHCP_ROUTER" "${args[4]}"
    change_setting "DHCP_LEASETIME" "${args[5]}"
    change_setting "PIHOLE_DOMAIN" "${args[6]}"
    change_setting "DHCP_IPv6" "${args[7]}"
    change_setting "DHCP_rapid_commit" "${args[8]}"

    # Remove possible old setting from file
    delete_dnsmasq_setting "dhcp-"
    delete_dnsmasq_setting "quiet-dhcp"

    # If a DHCP client claims that its name is "wpad", ignore that.
    # This fixes a security hole. see CERT Vulnerability VU#598349
    # We also ignore "localhost" as Windows behaves strangely if a
    # device claims this host name
    add_dnsmasq_setting "dhcp-name-match=set:hostname-ignore,wpad
dhcp-name-match=set:hostname-ignore,localhost
dhcp-ignore-names=tag:hostname-ignore"

    ProcessDHCPSettings

    RestartDNS
}

DisableDHCP() {
    change_setting "DHCP_ACTIVE" "false"

    # Remove possible old setting from file
    delete_dnsmasq_setting "dhcp-"
    delete_dnsmasq_setting "quiet-dhcp"

    ProcessDHCPSettings

    RestartDNS
}

SetWebUILayout() {
    change_setting "WEBUIBOXEDLAYOUT" "${args[2]}"
}

CustomizeAdLists() {
    list="/etc/pihole/adlists.list"

    if [[ "${args[2]}" == "enable" ]]; then
        sed -i "\\@${args[3]}@s/^#http/http/g" "${list}"
    elif [[ "${args[2]}" == "disable" ]]; then
        sed -i "\\@${args[3]}@s/^http/#http/g" "${list}"
    elif [[ "${args[2]}" == "add" ]]; then
        if [[ $(grep -c "^${args[3]}$" "${list}") -eq 0 ]] ; then
            echo "${args[3]}" >> ${list}
        fi
    elif [[ "${args[2]}" == "del" ]]; then
        var=$(echo "${args[3]}" | sed 's/\//\\\//g')
        sed -i "/${var}/Id" "${list}"
    else
        echo "Not permitted"
        return 1
    fi
}

SetPrivacyMode() {
    if [[ "${args[2]}" == "true" ]]; then
        change_setting "API_PRIVACY_MODE" "true"
    else
        change_setting "API_PRIVACY_MODE" "false"
    fi
}

ResolutionSettings() {
    typ="${args[2]}"
    state="${args[3]}"

    if [[ "${typ}" == "forward" ]]; then
        change_setting "API_GET_UPSTREAM_DNS_HOSTNAME" "${state}"
    elif [[ "${typ}" == "clients" ]]; then
        change_setting "API_GET_CLIENT_HOSTNAME" "${state}"
    fi
}

AddDHCPStaticAddress() {
    mac="${args[2]}"
    ip="${args[3]}"
    host="${args[4]}"

    if [[ "${ip}" == "noip" ]]; then
        # Static host name
        echo "dhcp-host=${mac},${host}" >> "${dhcpstaticconfig}"
    elif [[ "${host}" == "nohost" ]]; then
        # Static IP
        echo "dhcp-host=${mac},${ip}" >> "${dhcpstaticconfig}"
    else
        # Full info given
        echo "dhcp-host=${mac},${ip},${host}" >> "${dhcpstaticconfig}"
    fi
}

RemoveDHCPStaticAddress() {
    mac="${args[2]}"
    sed -i "/dhcp-host=${mac}.*/d" "${dhcpstaticconfig}"
}

SetHostRecord() {
    if [[ "${1}" == "-h" ]] || [[ "${1}" == "--help" ]]; then
        echo "Usage: pihole -a hostrecord <domain> [IPv4-address],[IPv6-address]
Example: 'pihole -a hostrecord home.domain.com 192.168.1.1,2001:db8:a0b:12f0::1'
Add a name to the DNS associated to an IPv4/IPv6 address

Options:
  \"\"                  Empty: Remove host record
  -h, --help          Show this help dialog"
        exit 0
    fi

    if [[ -n "${args[3]}" ]]; then
        change_setting "HOSTRECORD" "${args[2]},${args[3]}"
        echo -e "  ${TICK} Setting host record for ${args[2]} to ${args[3]}"
    else
        change_setting "HOSTRECORD" ""
        echo -e "  ${TICK} Removing host record"
    fi

    ProcessDNSSettings

    # Restart dnsmasq to load new configuration
    RestartDNS
}

SetAdminEmail() {
    if [[ "${1}" == "-h" ]] || [[ "${1}" == "--help" ]]; then
        echo "Usage: pihole -a email <address>
Example: 'pihole -a email admin@address.com'
Set an administrative contact address for the Block Page

Options:
  \"\"                  Empty: Remove admin contact
  -h, --help          Show this help dialog"
        exit 0
    fi

    if [[ -n "${args[2]}" ]]; then
        change_setting "ADMIN_EMAIL" "${args[2]}"
        echo -e "  ${TICK} Setting admin contact to ${args[2]}"
    else
        change_setting "ADMIN_EMAIL" ""
        echo -e "  ${TICK} Removing admin contact"
    fi
}

SetListeningMode() {
    source "${setupVars}"

    if [[ "$3" == "-h" ]] || [[ "$3" == "--help" ]]; then
        echo "Usage: pihole -a -i [interface]
Example: 'pihole -a -i local'
Specify dnsmasq's network interface listening behavior

Interfaces:
  local               Listen on all interfaces, but only allow queries from
                      devices that are at most one hop away (local devices)
  single              Listen only on ${PIHOLE_INTERFACE} interface
  all                 Listen on all interfaces, permit all origins"
        exit 0
  fi

    if [[ "${args[2]}" == "all" ]]; then
        echo -e "  ${INFO} Listening on all interfaces, permiting all origins. Please use a firewall!"
        change_setting "DNSMASQ_LISTENING" "all"
    elif [[ "${args[2]}" == "local" ]]; then
        echo -e "  ${INFO} Listening on all interfaces, permiting origins from one hop away (LAN)"
        change_setting "DNSMASQ_LISTENING" "local"
    else
        echo -e "  ${INFO} Listening only on interface ${PIHOLE_INTERFACE}"
        change_setting "DNSMASQ_LISTENING" "single"
    fi

    # Don't restart DNS server yet because other settings
    # will be applied afterwards if "-web" is set
    if [[ "${args[3]}" != "-web" ]]; then
        ProcessDNSSettings
        # Restart dnsmasq to load new configuration
        RestartDNS
    fi
}

Teleporter() {
    local datetimestamp=$(date "+%Y-%m-%d_%H-%M-%S")
    php /var/www/html/admin/scripts/pi-hole/php/teleporter.php > "pi-hole-teleporter_${datetimestamp}.tar.gz"
}

addAudit()
{
    shift # skip "-a"
    shift # skip "audit"
    for var in "$@"
    do
        echo "${var}" >> /etc/pihole/auditlog.list
    done
}

clearAudit()
{
    echo -n "" > /etc/pihole/auditlog.list
}

SetPrivacyLevel() {
    # Set privacy level. Minimum is 0, maximum is 4
    if [ "${args[2]}" -ge 0 ] && [ "${args[2]}" -le 4 ]; then
        changeFTLsetting "PRIVACYLEVEL" "${args[2]}"
    fi
}

ClearFilter(){

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

}

UpdateNord(){
        source "${nord}"
        stat="$(nordvpn status)"

if [ `echo $stat | grep -c "Connected" ` -gt 0 ]
then
        stat="$(nordvpn status)"

        status=$(echo $stat | grep -o -P '(?<=Status:).*(?=Current server:)') && status="$(echo -e "${status}" | sed -e 's/^[[:space:]]*//')"
        server=$(echo $stat | grep -o -P '(?<=Current server:).*(?=Country:)') && server="$(echo -e "${server}" | sed -e 's/^[[:space:]]*//')"
        country=$(echo $stat | grep -o -P '(?<=Country:).*(?=City:)') && country="$(echo -e "${country}" | sed -e 's/^[[:space:]]*//')"
        city=$(echo $stat | grep -o -P '(?<=City:).*(?=Your new IP:)') && city="$(echo -e "${city}" | sed -e 's/^[[:space:]]*//')"
        new_ip=$(echo $stat | grep -o -P '(?<=Your new IP:).*(?=Current technology:)') && new_ip="$(echo -e "${new_ip}" | sed -e 's/^[[:space:]]*//')"
        pro=$(echo $stat | grep -o -P '(?<=Current technology:).*(?=Transfer:)') && pro="$(echo -e "${pro}" | sed -e 's/^[[:space:]]*//')"
        transfer=$(echo $stat | grep -o -P '(?<=Transfer:).*(?=Uptime)') && transfer="$(echo -e "${transfer}" | sed -e 's/^[[:space:]]*//')"
        uptime=$(echo $stat | grep -o -P '(?<=Uptime:).*(?=seconds)') && uptime="$(echo -e "${uptime}" | sed -e 's/^[[:space:]]*//')"

        change_nord "STATUS" "$status"
        change_nord "SERVER" "$server"
        change_nord "COUNTRY" "$country"
        change_nord "CITY" "$city"
        change_nord "NEW_IP" "$new_ip"
        change_nord "PRO_VPN" "$pro"
        change_nord "TRANSFER" "$transfer"
        change_nord "UPTIME" "$uptime seconds"
else
        change_nord "STATUS" "Disconnected"
        change_nord "SERVER" "--"
        change_nord "COUNTRY" "--"
        change_nord "CITY" "--"
        change_nord "NEW_IP" "--"
        change_nord "PRO_VPN" "--"
        change_nord "TRANSFER" "--"
        change_nord "UPTIME" "--"
fi
}

NAT(){
	source "${arahasya}"
	if [[ "${PROTOCOL}" == "OpenVPN" ]]; then
		iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
  	elif [[ "${PROTOCOL}" == "Wireguard" ]]; then
		iptables -t nat -A POSTROUTING -o nordvpn+ -j MASQUERADE
	fi
        UpdateNord
}

ChangeVPNMode(){
	source "${arahasya}"
  if [[ "${VPN_MODE}" == "Enabled" ]]; then
	nordvpn d
        change_arahasya "VPN_MODE" "Disabled"
	ClearFilter
	NAT "eth0"
  elif [[ "${VPN_MODE}" == "Disabled" ]]; then
        change_arahasya "VPN_MODE" "Enabled"
  fi
	UpdateNord

	exit 0
}

ChangeDNSMode(){
        source "${arahasya}"

  if [[ "${DNS_CRYPT}" == "Enabled" ]]; then
	change_setting "PIHOLE_DNS_1" "8.8.8.8"
	delete_dnsmasq_setting "server"
	add_dnsmasq_setting "server" "8.8.8.8"
	RestartDNS
	change_arahasya "DNS_CRYPT" "Disabled"
  elif [[ "${DNS_CRYPT}" == "Disabled" ]]; then
	change_setting "PIHOLE_DNS_1" "127.0.0.1#4344"
        delete_dnsmasq_setting "server"
        add_dnsmasq_setting "server" "127.0.0.1#4344"
        RestartDNS
	change_arahasya "DNS_CRYPT" "Enabled"
  fi
}

ChangePiholeMode() {
	source "${setupVars}"
  if [[ "${BLOCKING_ENABLED}" == true ]]; then
        nohup bash -c "sudo pihole disable" &> /dev/null </dev/null &
	change_setting "BLOCKING_ENABLED" "false"
	exit 0
  elif [[ "${BLOCKING_ENABLED}" == false ]]; then
        nohup bash -c "sudo pihole enable" &> /dev/null </dev/null &
 	change_setting "BLOCKING_ENABLED" "true"
	exit 0
  fi

}

ChangeDefaults() {
        source "${arahasya}"
	change_arahasya "PROTOCOL" "${args[2]}"
	change_arahasya "DEFAULT_COUNTRY" "${args[3]}"
}

ChangeServer() {
	source "${arahasya}"
	pgrep openvpn | xargs sudo kill -9
  if [[ "${args[2]}" == "OpenVPN" ]]; then
	nohup bash -c "nordvpn set technology openvpn" &> /dev/null </dev/null &
  elif [[ "${args[2]}" == "Wireguard" ]]; then
	nohup bash -c "nordvpn set technology nordlynx" &> /dev/null </dev/null &
  fi

	/opt/pihole/arahasya/nord.sh "${args[3]}" "${NORD_MAIL}" "${NORD_PASS}"
	ClearFilter
	NAT
	UpdateNord

}

ChangeNord() {
        source "${arahasya}"
        change_arahasya "NORD_MAIL" "${args[2]}"
        change_arahasya "NORD_PASS" "${args[3]}"
}

OnBoot() {
	source "${arahasya}"

  if [[ "${PROTOCOL}" == "OpenVPN" ]]; then
        nohup bash -c "nordvpn set technology openvpn" &> /dev/null </dev/null &
  elif [[ "${PROTOCOL}" == "Wireguard" ]]; then
        nohup bash -c "nordvpn set technology nordlynx" &> /dev/null </dev/null &
  fi

  if [[ "${VPN_MODE}" == "Enabled" ]]; then

        /opt/pihole/arahasya/nord.sh "${DEFAULT_COUNTRY}" "${NORD_MAIL}" "${NORD_PASS}"
	ClearFilter
	NAT

  elif [[ "${VPN_MODE}" == "Disabled" ]]; then
	iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  fi
	UpdateNord

}

QuickConnect(){

  source "${arahasya}"
  if [[ "${PROTOCOL}" == "OpenVPN" ]]; then
        nohup bash -c "nordvpn set technology openvpn" &> /dev/null </dev/null &
  elif [[ "${PROTOCOL}" == "Wireguard" ]]; then
        nohup bash -c "nordvpn set technology nordlynx" &> /dev/null </dev/null &
  fi
	sudo /opt/pihole/arahasya/qconnect.sh "${NORD_MAIL}" "${NORD_PASS}"
	ClearFilter
	NAT
	UpdateNord
}

Disconnect(){
	nordvpn d
	pgrep openvpn | xargs sudo kill -9
	UpdateNord
}

ChangeWifiDetails(){
source "${hostapd}"

        systemctl stop hostapd
        change_hostapd "ssid" "${args[2]}"
        change_hostapd "wpa_passphrase" "${args[3]}"
        systemctl unmask hostapd
        systemctl enable hostapd
        systemctl start hostapd
}
ChangeInterface(){
source "${setupVars}"

        systemctl stop hostapd
        int="$(ip link | awk -F: '$0 !~ "lo|vir|et|p2|^[^0-9]"{print $2;getline}')"
        int="$(echo -e "${int}" | sed -e 's/^[[:space:]]*//')"
        find /etc/network/interfaces -type f -exec sed -i "s/wl.*$/${int}/g" {} \;
        find /etc/hostapd/hostapd.conf -type f -exec sed -i "s/interface=.*$/interface=${int}/g" {} \;
        change_setting "PIHOLE_INTERFACE" "${int}"
	ProcessDHCPSettings
	systemctl unmask hostapd
        systemctl enable hostapd
        systemctl start hostapd
}

main() {
    args=("$@")

    case "${args[1]}" in
        "-p" | "password"     ) SetWebPassword;;
        "-c" | "celsius"      ) unit="C"; SetTemperatureUnit;;
        "-f" | "fahrenheit"   ) unit="F"; SetTemperatureUnit;;
        "-k" | "kelvin"       ) unit="K"; SetTemperatureUnit;;
        "setdns"              ) SetDNSServers;;
        "setexcludedomains"   ) SetExcludeDomains;;
        "setexcludeclients"   ) SetExcludeClients;;
        "poweroff"            ) Poweroff;;
        "reboot"              ) Reboot;;
        "restartdns"          ) RestartDNS;;
        "setquerylog"         ) SetQueryLogOptions;;
        "enabledhcp"          ) EnableDHCP;;
        "disabledhcp"         ) DisableDHCP;;
        "layout"              ) SetWebUILayout;;
        "-h" | "--help"       ) helpFunc;;
        "privacymode"         ) SetPrivacyMode;;
        "resolve"             ) ResolutionSettings;;
        "addstaticdhcp"       ) AddDHCPStaticAddress;;
        "removestaticdhcp"    ) RemoveDHCPStaticAddress;;
        "-r" | "hostrecord"   ) SetHostRecord "$3";;
        "-e" | "email"        ) SetAdminEmail "$3";;
        "-i" | "interface"    ) SetListeningMode "$@";;
        "-t" | "teleporter"   ) Teleporter;;
        "adlist"              ) CustomizeAdLists;;
        "audit"               ) addAudit "$@";;
        "clearaudit"          ) clearAudit;;
        "-l" | "privacylevel" ) SetPrivacyLevel;;
	"changevpnmode"	      ) ChangeVPNMode;;
	"changednsmode"       ) ChangeDNSMode;;
	"changepiholemode"    ) ChangePiholeMode;;
	"changedefaults"      ) ChangeDefaults;;
	"changeserver"        ) ChangeServer;;
	"changenord"	      ) ChangeNord;;
	"updatenord"	      ) UpdateNord;;
	"onboot"	      ) OnBoot;;
	"quickconnect"        ) QuickConnect;;
	"disconnect"	      ) Disconnect;;
	"changewifidetails"   ) ChangeWifiDetails;;
	"changewifiint"       ) ChangeInterface;;
	"clearfilter"	      ) ClearFilter;;
        *                     ) helpFunc;;

    esac

    shift

    if [[ $# = 0 ]]; then
        helpFunc
    fi
}
