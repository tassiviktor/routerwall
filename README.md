# routerwall
Special firewall script for multiple networks, multiple WANs on single Linux firewall.

## The case
The client had two office with two networks. One of them had low speed internet with permanent IPv4 address (permanent IP is a requirement by a bureau for secure communication), the other one had high speed internet with dynamic IPv4 address. Both of them needs to use same servers in server room, and entire internal and external packet traffic needs to be controlled and managed by one redundant firewall. Both external interface had to be used at same time for different application.

This script is for easy firewall setup.

The main trick is using two separate routing table to manage external traffic.

## Usage

Make a directory in your server's /etc/init.d (or similar, depends on your distribution).

Copy routerwall.sh to this directory.

On Debian/Ubuntu based distros use:
```sh
service routerwall (start|stop|restart|reload)
```
