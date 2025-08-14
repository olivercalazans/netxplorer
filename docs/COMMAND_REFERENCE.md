<h1 align="center"> Command Reference </h1>

This document explains all commands and flags available in the project, describing their purpose and usage.

- [Port Scanning](#port-scanning)
- [Network Mapping](#network-mapping)
- [Banner Grabbing](#banner-grabbing)

<br>


# **Port Scanning**
Port Scanning is a technique used to identify which ports are open on a remote device or server. This process allows mapping the
services that are running and checking which ports are accessible from a network.

<br>


### Command syntax
```
xplorer pscan <ip_address> <flags>

# If you run manually:
sudo python3 ./main.py pscan <ip_address> <flags>
```

<br>

### Flags

| Small flag | Long flag | Example | Description |
|:----:|:----:|:----:|:----|
| -r | --random | - | Use the ports in a random order instead of scanning them sequentially. |
| -p | --port | -p 22,80 or -p 20-25 or -p 20-25,443 | Specify ports to scan. |
| -d | --delay | -d 0.5-3 or -d 1.5 | Add a delay between packet transmissions. [more](#flag-d) |
| -U | --UDP | - | Scan UDP ports |

<br>


<a id='flag-d'></a>
### • Delay
By using this flag, a delay time is applied between packet transmissions. You can set the delay time to be used, with two options
available: either specify a range or a fixed delay. For example, if you use the flag as ``-d 1-2.5``, the code will select delay times
randomly between 1 and 2.5 seconds. Alternatively, you can set a fixed delay by using the flag like this: ``-d 1.8``. In this case,
all packets will be sent with a delay of 1.8 seconds between them.

<br>


# Network Mapping

Network mapping is the process of discovering, identifying, and visualizing devices, connections, and communication paths within a
network to create a structured representation of its topology. It helps in monitoring traffic, detecting unauthorized devices,
assessing security risks, and optimizing performance, providing essential insights for network management and cybersecurity.

<br>

### Command syntax
```
xplorer netmap

# If you run manually:
sudo python3 ./main.py netmap
```
<br>



# **Banner Grabbing**
Banner Grabbing is a technique used in network security to gather information about a service running on a specific port of a remote
device. By sending a request to a server or device, the service may respond with a "banner" containing details about the software,
version, configurations, or even sensitive information. These banners are commonly returned by services such as HTTP, SSH, FTP, SMTP,
and others.

<br>

## Command syntax
```
xplorer banner <ip/hostname> <protocol> <flag>

# If runs manually
sudo python3 ./main.py banner <ip/hostname> <protocol> <flag>
```

<br>

| Small flag | Long flag | Example | Description |
|:----:|:----:|:----:|:----|
| -p | --port | -p 22| Specify ports to get banners. [more](#banner-port)|

<a id='banner-port'></a>
### • Port
The code uses the default port for banner grabbing. To use a different port, use the ``-p`` or ``--port`` flag.
