# Site-2-site WireGuard VPN set up guide

## Intro

This is a step by step guide on how to set up a WireGuard site-2-site VPN.

This solution connects both sites, secures the connection between both edge's LAN clients, and additionally, it routes all traffic going to the internet through site Y gateway as we can see in the following diagram.

![architecture](images/wireguard.png)

Is also good to keep in mind that for this solution, the client site acts as the source of internet connectivity and not the server site as should be expected. The reason for that is we have control over the gateway on the site Y but not on the site X.

The solution is perfect for sending the NanoPi client box to any friend in the world, and have access to his/her internet connection, no set up from their side is required, and you can also control the remote NanoPi from home.

Quite cool, isn't it? :)

## Requirements

* 2x NanoPi (I'm using Nanopi R2S)
* 2x MicroSD
* [Armbian distro](https://www.armbian.com/nanopi-r2s/)

## OS Installation

### Copy OS to SD Card

I will document the process with Etcher to write Armbian image into SD cards.

* Download [Etcher](https://www.etcher.io/)
* Insert the SD Card in the computer
* Use Ether to write the Armbian image you should have already downloaded (if not check the requirements section for the link)
* Once done, eject the card and insert it in the NanoPi R2S

### Booting NanoPi R2S

* Plug the ethernet cable
* Plug the power cable
* Armbian uses DHCP by default so once you know the IP address assigned from your DHCP server you can SSH into it
* SSH into the box by `ssh root@<IP>` and the default password is `1234`
* Immediately after login the first time it will ask the user to change `root` password and create a new regular user account

## Common set up

Run the steps below on both NanoPi:

* Set the hostname (replace `<NEW_HOSTNAME>` with the name you desire)

  ```shell
  sed -i "s/$HOSTNAME/<NEW_HOSTNAME>/g" /etc/hostname /etc/hosts
  ```

* Set the timezone

  ```shell
  dpkg-reconfigure tzdata
  ```

  Select the timezone where each NanoPi is going to be located.

* Upgrade the system to the latest version of all packages by running:

  ```shell
  apt update && apt -y upgrade
  ```

* Install [WireGuard](https://www.wireguard.com/install/)

  ```shell
  apt install -y wireguard
  ```

* Install iptables

  ```shell
  apt install -y iptables
  ```

## WireGuard Server setup

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

* Create a WireGuard config file

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

  # Set DNS resolver to our VPN client, preventing DNS leaks.
  DNS = 10.222.0.2

  # Enable ip forwarding in all interfaces
  PreUp = sysctl -w net.ipv4.ip_forward=1

  # Allowing any traffic from <LAN_NETWORK_INTERFACE> (internal) to go over %i (tunnel):
  PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o <LAN_NETWORK_INTERFACE> -j MASQUERADE

  PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o <LAN_NETWORK_INTERFACE> -j MASQUERADE
  PostDown = sysctl -w net.ipv4.ip_forward=0

  [Peer]
  # Configuration for the server's client Peer

  # The output of `echo "client private key" > wg pubkey`.
  PublicKey = <CLIENT_PUBLIC_KEY>

  # The IP address that this client is allowed to use.
  AllowedIPs = 0.0.0.0/0

  # Ensures that your home router does not kill the tunnel, by sending a ping
  # every 25 seconds.
  PersistentKeepalive = 25
  ```

  Pay attention to the `<CLIENT_PUBLIC_KEY>` because we still don't have this. **Caution: don't use the one from the server**.

  Replace `<LAN_NETWORK_INTERFACE>` for the name of the interface where the server is connected. On the NanoPi R2S, `eth0` is the WAN port and `lan0` is the LAN port, set the one you're using.

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

* Create a WireGuardconfig file

  ```shell
  nano /etc/wireguard/wg0.conf
  ```

  Add the content:

  ```text
  [Interface]
  # Configuration for the client

  # The IP address that this client will have on the WireGuard network.
  Address = 10.222.0.2/24

  # The private key you generated for the client previously.
  PrivateKey = <CLIENT_PRIVATE_KEY>

  # Enable traffic to be passed from the server network to the private subnet of the client
  PreUp = sysctl -w net.ipv4.ip_forward=1

  PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o <LAN_NETWORK_INTERFACE> -j MASQUERADE

  PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o <LAN_NETWORK_INTERFACE> -j MASQUERADE
  PostDown = sysctl -w net.ipv4.ip_forward=0

  [Peer]
  # Configuration for the server to connect to

  # The public key you generated for the server previously.
  PublicKey = <SERVER_PUBLIC_KEY>

  # The WireGuard server to connect to.
  Endpoint = <SERVER_PUBLIC_ENDPOINT>:<SERVER_PUBLIC_PORT>

  # The subnet this WireGuard VPN is in control of.
  AllowedIPs = 10.222.0.1/32

  # Ensures that your home router does not kill the tunnel, by sending a ping
  # every 25 seconds.
  PersistentKeepalive = 25
  ```

  Replace the following values:

  `<SERVER_PUBLIC_KEY>` with the public key generated in the server machine.
  `<SERVER_PUBLIC_ENDPOINT>` with the public DNS name of the WireGuard server.
  `<SERVER_PUBLIC_PORT>` with the port exposed on the server network.
  `<LAN_NETWORK_INTERFACE>` for the name of the interface where the server is connected. On the NanoPi R2S, `eth0` is the WAN port and `lan0` is the LAN port, set the one you're using.

* Now that we've set up both server and client we can start WireGuard on both machines:

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

  In case you see an error like the following, please reboot your NanoPi by running `reboot`:

  ```shell
  [#] ip link add wg0 type wireguard
  Error: Unknown device type.
  Unable to access interface: Protocol not supported
  [#] ip link delete dev wg0
  Cannot find device "wg0"
  ```

* Check WireGuardinterface

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

  At this point, you should be able to bring up both Wireguard interfaces and ping across both ends by:

  Running this in both ends:
  ```shell
  wg-quick up wg0
  ```

  And then try to ping the other host
  ```shell
  ping <REMOTE_WG_IP>
  ```

* Enable SystemD interface

  To make sure that systemd creates the interface every time the system starts, we have to enable it by:

  ```shell
  # systemctl enable wg-quick@wg0
  Created symlink /etc/systemd/system/multi-user.target.wants/wg-quick@wg0.service /lib/systemd/system/wg-quick@.service.
  ```

At this point, you should be able to ping the server from the client and through your new VPN.

`TIP`: In case we do changes in the WireGuard config and we want to apply them without interrupting the actual connection, run: `wg syncconf wg0 <(wg-quick strip wg0)`

## Dynamic DNS

A dynamic DNS server is useful when we can't have static IP addresses on the public network. This solution assumes that we don't have them and we actually don't need them because it is enough to have a dynamic DNS name set up to be good to go. I'm personally using [YDNS](https://ydns.io), but there are hundreds of services available out there.

We have to run this in both boxes with different names (of course).

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
  YDNS_HOST="<HOST>" # This have to be different on both boxes
  [...]
  ```

* Add the script as a PreUp condition for WireGuard config

  ```shell
  nano /etc/wireguard/wg0.conf
  ```

  Add the following content inside the `[Interface]` section

  With the content:

  ```text
  PreUp = /usr/local/bin/updater.sh -V
  ```

# Extra good practices and optional features

## Watchdog

### What is a watchdog

A watchdog is an electronic timer used for monitoring hardware and software functionality. The software uses a watchdog timer to detect and recover fatal failures.

### Why using a watchdog

We use a watchdog to make sure we have a functional VPN. If a problem comes up, the computer should be able to recover itself back to a functional state. We will configure the board to reboot if WireGuard link is down for too long, or a specific process isn’t running any more.

### Setup the watchdog software

* Install the watchdog software

  ```shell
  apt install watchdog
  ```

* Configure the watchdog to monitor WireGuard network

  ```shell
  nano /etc/watchdog.conf
  ```

  Edit the following lines:

  ```text
  log-dir = /var/log.hdd/watchdog

  interface = wg0

  ping = <REMOTE_WG_IP>

  retry-timeout = 300

  interval = 30
  ```

* Enable and start the service

  ```shell
  systemctl stop watchdog
  systemctl enable watchdog
  systemctl start watchdog
  ```

## Reverse SSH to WireGuard Client

As we want to be able to control the WireGuard client box from our local network without relying on the VPN network, this solution setups up a reverse SSH tunnel.

To achieve that we're going to use Sidedoor. Additionally, find the official repo and documentation [here](https://github.com/daradib/sidedoor)

Sidedoor set up is very straight forward:

* Installation **(on the client box)**

  ```shell
  apt install sidedoor
  ```

* Generate SSH private key to access the remote server **(on the client box)**

  ```shell
  ssh-keygen -t rsa -N '' -f /etc/sidedoor/id_rsa
  ```

* Edit sidedoor configuration file **(on the client box)**

  ```shell
  nano /etc/default/sidedoor
  ```

  We've to change `OPTIONS` and `REMOTE_SERVER`. So, for `OPTIONS` use:

  ```shell
  OPTIONS='-R <WIREGUARD_CLIENT_PUBLIC_DNS>:<BIND_PORT_ON_WIREGUARD_SERVER>:localhost:<WIREGUARD_CLIENT_SSHD_PORT> -p <WIREGUARD_SERVER_PUBLIC_PORT>'
  ```

  `<WIREGUARD_CLIENT_PUBLIC_DNS>`: The public DNS/IP for the WireGuard client box.

  `<BIND_PORT_ON_WIREGUARD_SERVER>`: The port where WireGuard client SSHD will be bound on WireGuard server. Choose something higher than 1024.

  `<WIREGUARD_CLIENT_SSHD_PORT>`: The port where SSHD is listening on the WireGuard client, usually 22.

  `<WIREGUARD_SERVER_PUBLIC_PORT>`: The public port where SSHD for WireGuard server box is exposed. In case it's the standard 22 you can just remove the -p option.

  For `REMOTE_SERVER` use:

  ```shell
  REMOTE_SERVER=<USER>@<WIREGUARD_SERVER_PUBLIC_DNS>
  ```

  `<USER>`: user to log in on WireGuard server box.

  `<WIREGUARD_SERVER_PUBLIC_DNS>`: The public DNS/IP for the WireGuard server box.

* Add WireGuard public key to WireGuard server **(on the server box)**

  To make the tunnel working without any user interaction, we've to enable public-key authentication to WireGuard Server's SSH daemon.
  To do that, copy the content of the file `/etc/sidedoor/id_rsa.pub` on the WireGuard client box and paste it inside the desired user's `~/.ssh/authorized_keys` file inside WireGuard server box.

* Enable forwarded ports on SSH daemon **(on the server box)**

  SSH doesn’t by default allow remote hosts to forwarded ports. We're going to enable this only to the desired user by editing `/etc/ssh/sshd_config`:

  ```shell
  nano /etc/ssh/sshd_config
  ```

  Add the following lines at the bottom of the file:

  ```shell
  Match User <USER>
    GatewayPorts yes
  ```

  `<USER>`: user specified on the Sidedoor config file.

* Restart SSHD service **(on the server box)**

  ```shell
  systemctl restart ssh
  ```

* Restart the Sidedoor service to apply changes **(on the client box)**

  ```shell
  systemctl restart sidedoor
  ```

Now we can check Sidedoor output to see if there are any errors by `systemctl status sidedoor`, but if not, we're ready to go and we should be able to login into WireGuard client box from WireGuard server network by running:

```shell
ssh <USER>@<WIREGUARD_CLIENT_PUBLIC_DNS> -W localhost:<BIND_PORT_ON_WIREGUARD_SERVER> <USER>@<WIREGUARD_SERVER_LAN_IP>
```

## Unattended security updates

Security updates are crucial to keep our system safe from threats. Even tho we don't have so many services open to the world, one bug is enough to allow attackers to break into our system.

```shell
apt install -y unattended-upgrades
```

The default set up of this package installs security updates for the current release. If you want to update all packages when available, take a look at the `/etc/apt/apt.conf.d/50unattended-upgrades`.

To test the package behaviour, we can run:
```shell
unattended-upgrade --debug --dry-run
```

## Log rotate

Armbian in NanoPi has the logs located in two directories. The first is a ramdisk (`/var/log/`) which is usually around 50MB size. This is definitely not enough to keep our logs for more than a week, and depending on how much connection we have a day will not even hold 24h of logs before you start getting errors such as:

```shell
cannot write to log file '/var/log/xxx.log': No space left on device
```

The second one is located in the root partition (`/var/log.hdd/`).

The good practice here would be to save all logs in the disk, or at least safekeeping a compressed copy in the disk for security.

But if you're using this at home and you don't care much about them apart from realtime debugging when errors happen, then you can basically discard all logs after a day using `logrotate` :)

Let's start by increasing the `/var/log` ramdisk from 50MB to 100MB.

Edit `/etc/default/armbian-ramlog` and set `SIZE` to 100M.

apply the changes by running `systemctl restart armbian-ramlog.service`

Now, let's move to Logrotate. The main config file is located at `/etc/logrotate.conf` and then all sort of directory specific Logrotate definitions inside `/etc/logrotate.d`, let's first edit the default behaviour by:

```shell
nano /etc/logrotate.conf
```

Replace the content of the file for this:
```config
# rotate log files daily
daily

# Old versions are removed
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
/var/log.hdd/*.log /var/log.hdd/*/*.log {
  daily
  rotate 0
  create
  missingok
}

/var/log/*.log /var/log/*/*.log {
  daily
  rotate 0
  create
  missingok
}
```

What this config is going to do is rotate all log files in `/var/log/` and `/var/log.hdd` as well their child directories.

This can be tested by:

```shell
logrotate -d /etc/logrotate.d/nanopi
```

The `-d` flag will list each log file it is considering to rotate.

As Logrotate is set up to run daily via Cron we don't have to do any further change.

## SSH hardening

These are just some good practices to hardening our SSH daemons, especially when they are publically available.

Add those lines somewhere inside the `/etc/ssh/sshd_config` file:

```shell
# Disable root login
PermitRootLogin no

# Disable password authentication
ChallengeResponseAuthentication no
PasswordAuthentication no

# Limit daemon to only listen on localhost (only for WireGuard client when we enable reverse SSH)
ListenAddress ::1
ListenAddress 127.0.0.1
```

To apply the previous config, just restart the SSH daemon:

```shell
systemctl restart ssh
```

<!--
## Firewall

Edit the content of `/etc/iptables.conf` and add:

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
``` -->

# References

To build this guide, I've used several references, from blogs, other how-to and man pages.

* [https://zach.bloomqu.ist/blog/2019/11/site-to-site-wireguard-vpn.html](https://zach.bloomqu.ist/blog/2019/11/site-to-site-wireguard-vpn.html)
* [https://www.wireguard.com/quickstart/](https://www.wireguard.com/quickstart/)
* [https://danrl.com/blog/2016/travel-wifi/](https://danrl.com/blog/2016/travel-wifi/)