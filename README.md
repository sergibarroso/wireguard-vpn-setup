# nanopi-vpn

## Intro

This repo is a how-to set a WireGuard site-2-site vpn with Nanopi

## Requirements

* 2x NanoPi (I'm using Nanopi R2S)
* 2x MicroSD
* [Armbian distro](https://www.armbian.com/nanopi-r2s/)

## Copy OS to SD Card

I will document the process with Etcher to write Armbian image into SD cards.

* Download [Etcher](https://www.etcher.io/)
* Insert the SD Card in the computer
* Use Ether to write the Armbian image you should have already downloaded (if not check the requirements section for the link)
* Once done, eject the card and insert it in the NanoPi R2S

## Booting NanoPi R2S

* Plug the ethernet cable
* Plug the power cable
* Armbian uses DHCP by default so once you know the IP address assigned from your DHCP server you can SSH into it
* SSH into the box by `ssh root@<IP>` and the default password is `1234`
* Immediately after login the first time it will ask the user to change `root` password and create a new normal user account

## Basic Setup

The steps below should be performed in all systems that you have.

* Set the host name

  ```shell
  sed -i 's/nanopi-r2s/<NEW_HOSTNAME>/g' /etc/hostname /etc/hosts
  ```

* Set the timezone

  ```shell
  dpkg-reconfigure tzdata
  ```

  And select the timezone your server it is located.

* Upgrade the system to the latest version of all packages by running:

  ```shell
  apt update && apt -y upgrade
  ```

* Install [WireGuard](https://www.wireguard.com/install/)

  ```shell
  apt install -y wireguard
  ```

* Install nftables

  ```shell
  apt install -y nftables
  ```

## WireGuard Server Setup

* Create a directory to store the keys and set strict permissions

  ```shell
  mkdir /etc/wireguard/keys
  chmod 700 /etc/wireguard/keys
  ```

* Generate the server's private key by running the following command

  ```shell
  wg genkey > /etc/wireguard/keys/private.key
  ```

* Use the output from the previous command to generate the server's public key

  ```shell
  cat /etc/wireguard/keys/private.key | wg pubkey > /etc/wireguard/keys/public.key
  ```

* Set strict permissions on key files

  ```shell
  chmod 400 /etc/wireguard/keys/*.key
  ```

* Create a wireguard config file

  ```shell
  nano /etc/wireguard/wg0.conf
  ```

  Add the content:

  ```text
  [Interface]
  # Configuration for the server

  # Set the IP subnet that will be used for the WireGuard network.
  # 10.222.0.1 - 10.222.0.255 is a memorable preset that is unlikely to conflict.
  Address = 10.222.0.1/24

  # The port that will be used to listen to connections. 51820 is the default
  ListenPort = 51820

  # The output of `wg genkey` for the server.
  PrivateKey = <SERVER_PRIVATE_KEY>

  # Enable traffic to be passed from the client network to the private subnet of the server
  PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o <LAN_NETWORK_INTERFACE> -j MASQUERADE
  PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o <LAN_NETWORK_INTERFACE> -j MASQUERADE

  [Peer]
  # Configuration for the server's client Peer

  # The output of `echo "client private key" > wg pubkey`.
  PublicKey = <CLIENT_PUBLIC_KEY>

  # The IP address that this client is allowed to use.
  AllowedIPs = 10.222.0.2/32,<CLIENT_LAN_NETWORK>

  # Ensures that your home router does not kill the tunnel, by sending a ping
  # every 25 seconds.
  PersistentKeepalive = 25
  ```

  Pay attention to the `<CLIENT_PUBLIC_KEY>` because we still don't have this. **Caution: don't use the server one**.

  Replace `<LAN_NETWORK_INTERFACE>` for the name of interface where server is connected. Usually is `eth0` for WAN port and `lan0` for LAN port on the NanoPi R2S.

  And finally `<CLIENT_LAN_NETWORK>` for the network address you will use for your client's network range. E.g. `192.168.0.0/24`

## WireGuard Client Setup

* Create a directory to store the keys and set strict permissions

  ```shell
  mkdir /etc/wireguard/keys
  chmod 700 /etc/wireguard/keys
  ```

* Generate client's private key

  ```shell
  wg genkey > /etc/wireguard/keys/private.key
  ```

* Use the output from the previous command to generate the client's public key

  ```shell
  cat /etc/wireguard/keys/private.key | wg pubkey > /etc/wireguard/keys/public.key
  ```

  At this point, you can take the content of the client's public key and add it to the server's WireGuard config on the [previous section](#wireguard-server-setup).

* Set strict permissions on key files

  ```shell
  chmod 400 /etc/wireguard/keys/*.key
  ```

* Create a wireguard config file

  ```shell
  nano /etc/wireguard/wg0.conf
  ```

  Add the content:

  ```text
  [Interface]
  # Configuration for the client

  # The IP address that this client will have on the WireGuard network.
  Address = 10.222.0.2/32

  # The private key you generated for the client previously.
  PrivateKey = <CLIENT_PRIVATE_KEY>

  # Enable traffic to be passed from the server network to the private subnet of the client
  PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o <LAN_NETWORK_INTERFACE> -j MASQUERADE
  PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o <LAN_NETWORK_INTERFACE> -j MASQUERADE

  [Peer]
  # Configuration for the server to connect to

  # The public key you generated for the server previously.
  PublicKey = <SERVER_PUBLIC_KEY>

  # The WireGuard server to connect to.
  Endpoint = <SERVER_PUBLIC_ENDPOINT>:<SERVER_PUBLIC_PORT>

  # The subnet this WireGuard VPN is in control of.
  AllowedIPs = 0.0.0.0/0,::/0

  # Ensures that your home router does not kill the tunnel, by sending a ping
  # every 25 seconds.
  PersistentKeepalive = 25
  ```
  Replace `<SERVER_PUBLIC_KEY>` with the public key generated in the server machine.

  Also `<LAN_NETWORK_INTERFACE>` for the name of interface where server is connected. Usually is `eth0` for WAN port and `lan0` for LAN port on the NanoPi R2S.

  And finally `<CLIENT_LAN_NETWORK>` for the network address you will use for your client's network range. E.g. `192.168.0.0/24`

* Now that we've setup both server and client we can start WireGuard on both machines:

  ```shell
  wg-quick up wg0
  ```

  You should see an output like:

  ```shell
  [#] ip link add wg0 type wireguard
  [#] wg setconf wg0 /dev/fd/63
  [#] ip -4 address add 10.222.0.1/24 dev wg0
  [#] ip link set mtu 1420 up dev wg0
  ```

  In case you see an error like the following, please reboot your nanopi by running `reboot`:

  ```shell
  [#] ip link add wg0 type wireguard
  Error: Unknown device type.
  Unable to access interface: Protocol not supported
  [#] ip link delete dev wg0
  Cannot find device "wg0"
  ```

* Check wireguard interface

  ```shell
  # wg show
  interface: wg0
    public key: <SERVER_PUBLIC_KEY>
    private key: (hidden)
    listening port: 51820

  peer: <CLIENT_PUBLIC_KEY>
    endpoint: <CLIENT_IP>:36010
    allowed ips: 10.222.0.2/32
    latest handshake: 32 seconds ago
    transfer: 732 B received, 500 B sent
    persistent keepalive: every 25 seconds
  ```

  If you don't have any `peer` definition means that the tunnel didn't work.

  At this point you should be able to bring up both Wireguard interfaces and ping across both ends by:

  Running this in both ends:
  ```shell
  wg-quick up wg0
  ```

  And then try to ping the other host
  ```shell
  ping <REMOTE_WG_IP>
  ```

* Enable systemd interface

  To make sure that systemd creates the interface everytime the system starts we have to enable it by:

  ```shell
  # systemctl enable wg-quick@wg0
  Created symlink /etc/systemd/system/multi-user.target.wants/wg-quick@wg0.service → /lib/systemd/system/wg-quick@.service.
  ```

At this point, you should be able to do ping the server from the client and through your new VPN.

```shell

```

But still work to do, as what we want to achieve is that the NanoPI client acts as a gateway for all our network connections.

## Setup LAN interface

* Set static IP for the LAN interface

```shell

```

## DHCP Server

* Install the server

  ```shell
  apt install -y isc-dhcp-server
  ```

* Edit the config file to set what interfaces will listen for DHCP requests

  ```shell
  nano /etc/default/isc-dhcp-server
  ```

  Add the interface that you prefer, for NanoPI the LAN interface is usually `lan0`

  ```shell
  INTERFACESv4="lan0"
  INTERFACESv6="lan0" # Only if you need IPv6, otherwise comment the line
  ```

* Now edit the server config file to set its behaviour

  ```shell
  nano /etc/dhcp/dhcpd.conf
  ```

  ```shell
  # dhcpd.conf
  #

  default-lease-time 3600;
  max-lease-time 7200;

  # If this DHCP server is the official DHCP server for the local
  # network, the authoritative directive should be uncommented.
  authoritative;

  # Disable the dynamic DNS:
  ddns-update-style none;

  # Set Deny decline messages to avoid DoS attack againest your dhcp server.
  # The client device can send DHCPDECLINE message many times that can exhaust
  # the DHCP server’s pool of IP addresses, causing the DHCP server to forget old address allocations:
  deny declines;

  # Disable support older BOOTP clients:
  deny bootp;

  # Use Google public DNS server (or use faster values that your internet provider gave you!):
  option domain-name-servers 8.8.8.8, 8.8.4.4;

  # DHCP Leasing
  subnet 192.168.100.0 netmask 255.255.255.0 {
    range 192.168.100.100 192.168.100.200;
    option subnet-mask 255.255.255.0;
    option broadcast-address 192.168.100.255;
    option routers 192.168.100.1;
  }
  ```

* Enable DHCP service

  ```shell
  systemctl enable isc-dhcp-server
  ```

* Start DHCP service

  ```shell
  systemctl start isc-dhcp-server
  ```

* Enable DHCP Server to start at every server run

  ```shell
  systemctl enable isc-dhcp-server.service
  ```

## Extra good practices setup

### Unattended security updates

Security updates are crucial to keep our system safe from threads. Eventhow we don't have so many services open to the world, one bug is enough to allow attackers to break into our system.

```shell
apt install -y unattended-upgrades
```

The default setup of this package installs security updates for the current release. If you want to update all packages when available take a look at the `/etc/apt/apt.conf.d/50unattended-upgrades`.

To test the package behaviour we can run:
```shell
unattended-upgrade --debug --dry-run
```

### Log rotate

Armbian in Nanopi has the logs located in two directories. The first is a ram disk (`/var/log/`) which is usually around 50MB size. This is definitely not enough to keep our logs for more than a week, and depending on how much connection we have a day will not even hold 24h of logs before you start getting errors such as:

```shell
cannot write to log file '/var/log/xxx.log': No space left on device
```

The second one is located in the root partition (`/var/log.hdd/`).

The good practice here would be to save all logs in the disk, or at least safekeeping a compressed copy in the disk for security.

But if you're using this at home and you don't care much about them apart from realtime debugging when errors happen, then you can basically discards all logs after some hours using `logrotate` :)

Logrotate has a main config file located at `/etc/logrotate.conf` and then all sort of per directory logrotate definitions inside `/etc/logrotate.d`, let's first edit the default behaviour by:

```shell
nano /etc/logrotate.conf
```

Replace the content of the file for this:
```config
# rotate log files daily
daily

# Old version are removed
rotate 0

# create new (empty) log files after rotating old ones
create

# uncomment this if you want your log files compressed
compress

# packages drop log rotation information into this directory
include /etc/logrotate.d
```

Now let's see what we have inside `/etc/logrotate.d/` directory:

```shell
ls /etc/logrotate.d/
alternatives  apt  armbian-hardware-monitor  btmp  chrony  dpkg  rsyslog  wtmp
```

And what I'm going to do here is delete everything and create a new config file called `nanopi`. So let's remove everything:

```shell
rm /etc/logrotate.d/*
```

And now let's create the new config file at `/etc/logrotate.d/nanopi` with the following content:

```config
/var/log/*.log /var/log/*/*.log {
  daily
  rotate 0
  create
}

/var/log.hdd/*.log /var/log.hdd/*/*.log {
  daily
  rotate 0
  create
}
```

What this config is going to do is rotate all log files in `/var/log/` and `/var/log.hdd` as well their child directories.

This can be tested by:

```shell
logrotate -d /etc/logrotate.d/nanopi
```

the `-d` flag will list each log file it is considering to rotate.

As logrotate is setup to run daily via cron we don't have to do any further change.

### SSH hardening

### Reverse SSH to WireGuard Server

* Install SideDoor

  ```shell
  apt install sidedoor
  ```

### Firewall

Edit the content of `/etc/nftables.conf` and add:

```shell
# firewall
table ip filter {
	# allow all packets sent by the firewall machine itself
	chain output {
		type filter hook output priority 100; policy accept;
	}

	# allow LAN to firewall, disallow WAN to firewall
	chain input {
		type filter hook input priority 0; policy accept;
		iifname "lan0" accept
		iifname "eth0" drop
	}

	# allow packets from LAN to WAN, and WAN to LAN if LAN initiated the connection
	chain forward {
		type filter hook forward priority 0; policy drop;
		iifname "lan0" oifname "eth0" accept
		iifname "eth0" oifname "lan0" ct state related,established accept
	}
}

# NAT
table ip nat {
	chain prerouting {
		type nat hook prerouting priority 0; policy accept;
	}

	# for all packets to WAN, after routing, replace source address with primary IP of WAN interface
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		oifname "wan0" masquerade
	}
}z
```

### Dynamic DNS

Even if the server ip changes we should keep track of it via Dynamic DNS. I´m personally using [YDNS](https://ydns.io) but feel free to use any other.

* Installing curl

  ```shell
  apt install -y curl
  ```

* Get the YDNS updater

  ```shell
  curl -o /usr/local/bin/updater.sh https://raw.githubusercontent.com/ydns/bash-updater/master/updater.sh
  ```

* Give it execution permissions

  ```shell
  chmod +x /usr/local/bin/updater.sh
  ```

* Edit the file and set your information

  ```shell
  # nano /usr/local/bin/updater.sh
  [...]
  YDNS_USER="<EMAIL>"
  YDNS_PASSWD="<SECRET>"
  YDNS_HOST="<HOST>"
  [...]
  ```

* Create a cron entry by creating a cron file

  ```shell
  nano /etc/cron.d/ydns-updater
  ```

  With the content:

  ```shell
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

  # Update YDNS every 15 minutes everyday
  */15 * * * * /usr/local/bin/updater.sh > /dev/null
  ```

### Remove unused packages

```shell
apt remove -y apt remove wpasupplicant wireless-tools wireless-regdb hostapd iw crda
```

### Reverse SSH

In case the Wireguard box sits behind a NAT firewall and you can't control port forwarding rules you can setup a reverse SSH tunnel.

I personally use sidedoor, which is an easy way to setup and maintain SSH tunnels, just follow the official documentation [here](https://github.com/daradib/sidedoor)

# References

In orther to build this how to I've used several references, from blogs, to other how-to to man pages.

* [https://zach.bloomqu.ist/blog/2019/11/site-to-site-wireguard-vpn.html](https://zach.bloomqu.ist/blog/2019/11/site-to-site-wireguard-vpn.html)