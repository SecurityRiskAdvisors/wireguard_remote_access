# wireguard_remote_access
A python3 script to manage a Wireguard remote access server.

## Introduction
This script has come about because we often need to run and manage Wireguard servers for remote access purposes.
More often than not, the person managing it, has to manage IP addresses, keys and users. This script abstracts all that away from the administrator and manages that internally.

It _attempts_ to maintain the security parameters of Wireguard, although it may not be very successful in doing so.
This is very much a first version and PRs and issues are welcome.

_The script requires wireguard-tools (wg) to be installed to create the config files._

```
python3 wireguard_remote_access.py -h
usage: wireguard_remote_access.py [-h] [--config CONFIG] [--reset]
                                  [--restart-service {yes,y,no,n,ask,a}]

Generates a wireguard config for users

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        path to the config file. Defaults to:
                        /etc/wireguard/users.ini
  --reset               clear existing cache and regenerate all config files
  --restart-service {yes,y,no,n,ask,a}, -r {yes,y,no,n,ask,a}
                        restart wireguard service after updating file

```

<!---
### Demo

![Demo](https://github.com/SecurityRiskAdvisors/doc-repo/raw/master/llmnr_sphinx_demo.gif)
-->

## Usage
- Download or install `wireguard-tools`. You _technically_ don't need the kernel modules to use the script, but if you want to run the server it will help.

- Clone the `wireguard_remote_access` repo.

- Check that you have all the dependencies installed.
```
$ make
pwd
/wireguard_remote_access
command -v python3
/usr/bin/python3
command -v wg
/usr/bin/wg
```
- (Optional) Install the script and configuration file
```
$ make install
```
- Update the config file with the appropriate data.
_Make sure to update PublicIP and PublicPort with the correct info for your server_
- Run the script to generate the configs
```
$ python3 wireguard_remote_access.py -c /path/to/config.ini
```
- The script will fail unless you change the following compoments:
  - The example Server PrivateKey
  - The example Peer PrivateKey
  - The example PublicIP

- You will get a data-uri output and a link (https://securityriskadvisors.github.io/wireguard_remote_access/download_config) to download the configs.
  - You can also use the bookmarklet (found on the above page) to download the config files.

- After the script completes, it will ask if you would like to restart `wg-quick` for a detected wireguard interface (e.g. `wg0` or `wg1`).
_You can disable this check by passing `-r no` on invocation._

