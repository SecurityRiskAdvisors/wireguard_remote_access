#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ipaddress
import os
import argparse
import configparser
import subprocess
import json
import random
import time
import io
import base64
import re

import zipfile
import zlib

import sys

if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

# Set up statics for script
MAX_CONFIG_SIZE = 1 * 2 ** 20

DEFAULT_USERS_CONFIG = "/etc/wireguard/users.ini"

server_config = ["[Interface]", "Address = {}", "ListenPort = {}", "PrivateKey = {}"]

server_peers = [
    "# {}",  # This will be the peer name
    "[Peer]",
    "PublicKey = {}",
    "AllowedIPs = {}",
]

client_config = [
    "# {}",  # This will be the peer name
    "[Interface]",
    "PrivateKey = {}",
    "Address = {}",
    "{}DNS = {}",
    "# {}",  # Server metadata
    "[Peer]",
    "PublicKey = {}",
    "AllowedIPs = {}",
    "Endpoint = {}",
    "PersistentKeepalive = {}",
]


def err_print(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


regex_key = "^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$"

# Taken from here: https://stackoverflow.com/a/1094933
def sizeof_fmt(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, "Yi", suffix)


def parse_parameters(config_file_contents):
    config = configparser.ConfigParser(interpolation=None, allow_no_value=False)

    try:
        config.read_string(config_file_contents)
    except configparser.Error:
        raise ValueError(
            "Malformed config file -- could not parse config file"
        ) from None

    try:
        ipaddress.ip_network(config["General"].get("Network"))
    except ValueError:
        raise ValueError("Network needs to be a valid network") from None

    if (
        config["General"].get("WiregardConfig") == None
        or config["General"].get("WiregardConfig") == ""
    ):
        raise ValueError("WiregardConfig needs to be an actual file path")

    if config["General"].get("State") == None or config["General"].get("State") == "":
        raise ValueError("State needs to be an actual file path")

    try:
        verify_key(config["Server"].get("PrivateKey"))
    except ValueError:
        raise ValueError(
            "Key for does not appear to be valid. Key: {key}".format(
                key=config["Server"].get("PrivateKey")
            )
        ) from None

    if (
        config["Server"].get("PrivateKey")
        == "2HMaEPYJGhcX/vBNbvAo4wah72qOyt5ZT1WeIwKFWnI="
    ):
        raise ValueError(
            "Server PrivateKey is using an example key. Generate a new key using `wg genkey`"
        ) from None

    try:
        server_ip = ipaddress.ip_address(config["Server"].get("Address"))
        if server_ip not in ipaddress.ip_network(config["General"].get("Network")):
            raise ValueError(
                "Server Address ({}) not in Network ({}).".format(
                    config["Server"].get("Address"), config["General"].get("Network")
                )
            )
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(
            "Could not parse IP address: {}. Error: {}".format(
                config["Server"].get("Address"), str(e)
            )
        ) from e

    try:
        config["Server"].getint("ListenPort")
    except ValueError:
        raise ValueError("ListenPort needs to be an integer") from None

    try:
        if config["Server"].get("PrivateKey") is None:
            raise ValueError("Server PrivateKey cannot be empty.")
    except ValueError:
        raise
    except KeyError:
        raise ValueError("Server PrivateKey cannot be empty.") from None

    if config["PeerConfig"].get("PublicIP") == "93.184.216.34":
        raise ValueError(
            "You probably don't want example.com's IP as your PublicIP, please update."
        )

    if len(config["Peers"].items()) == 0:
        raise ValueError("You need to have at least 1 peer.")

    return config


def read_file(filepath, max_size=MAX_CONFIG_SIZE):
    file_size = os.path.getsize(filepath)
    if file_size < max_size:
        with open(filepath) as fp_filepath:
            file_contents = fp_filepath.read(file_size)
            eof = fp_filepath.read(1)
            pass

        if len(eof) > 0:
            raise ValueError(
                "File changed after program execution, please ensure file is not corrupted"
            )
        return file_contents
        pass
    else:
        raise ValueError(
            "Config file is larger than "
            + sizeof_fmt(max_size)
            + ", please ensure that the file is correctly formatted"
        )
    pass


def parse_config(config_file=DEFAULT_USERS_CONFIG):

    try:
        config_file_contents = read_file(config_file)
    except OSError as e:
        raise ValueError(
            "Could not parse users config file. Error: %s" % (str(e))
        ) from None

    return parse_parameters(config_file_contents)


def setup_state(state_file):
    size_state_file = 100 * MAX_CONFIG_SIZE

    retry = 0
    while True:
        try:
            open(state_file, mode="x").close()
            return {"users": {}, "addrs": {}, "keys": {}}
        except FileExistsError:
            # A state file already exists so let's try reading it
            json_state = read_file(state_file, size_state_file)
            if len(json_state) > 0:
                return json.loads(json_state)
            else:
                return {"users": {}, "addrs": {}, "keys": {}}
        except OSError as e:
            # Something else happened so let's try sleeping and then retrying
            if retry > 2:
                raise

            err_print(
                "Could not write {} due to {}. Retrying...".format(state_file, str(e))
            )
            retry += 1
            time.sleep(1 * retry)
        except:
            raise

        pass  # whileloop
    pass  # enddef


def check_wireguard_conf(wireguard_path):
    retry = 0
    while True:
        try:
            open(wireguard_path, mode="x").close()
            return
        except FileExistsError:
            # backup file and write the new one
            os.rename(
                wireguard_path,
                os.path.join(
                    os.path.dirname(wireguard_path),
                    "{}.bak.{}".format(
                        os.path.basename(wireguard_path), int(time.time())
                    ),
                ),
            )
            open(wireguard_path, mode="x").close()
            return
        except OSError as e:
            if retry > 2:
                raise

            err_print(
                "Could not create {} due to {}. Retrying...".format(
                    wireguard_path, str(e)
                )
            )
            retry += 1
            time.sleep(1 * retry)
        except:
            raise

        pass  # whileloop
    pass  # enddef


def create_config(
    user, key, hosts, d_state, cidr_mask, config, server_pub_key, configs_zip, runid
):
    if key == "auto":
        try:
            user_key = run_command("wg genkey")
        except subprocess.CalledProcessError as e:
            raise ValueError(
                "Could not generate private key for {}. Error: {}".format(
                    user, e.output.decode("utf-8").strip()
                )
            ) from None
    else:
        user_key = key
        try:
            verify_key(user_key)
        except ValueError:
            raise ValueError(
                "Key for {user} does not appear to be valid. Key: {key}".format(
                    user=user, key=key
                )
            ) from None
        pass
    addr = str(hosts.pop())
    try:
        client_pub_key = run_command("echo -n {} | wg pubkey".format(user_key))
    except subprocess.CalledProcessError as e:
        raise ValueError(
            "Could not generate public key for {}. Error: {}".format(
                user, e.output.decode("utf-8").strip()
            )
        ) from None

    d_client = {"Address": addr, "username": user, "PublicKey": client_pub_key, "runid": runid}
    d_state["users"][user] = d_client
    d_state["addrs"][str(addr)] = user
    d_state["keys"][client_pub_key] = user

    client_address = "{addr}/{mask}".format(addr=addr, mask=cidr_mask)
    dns_status = "#"
    if config["PeerConfig"].get("DNS") is not None:
        dns_status = ""
        pass

    wg_config = "\r\n".join(client_config).format(
        user,
        user_key,
        client_address,
        dns_status,
        config["PeerConfig"].get("DNS", fallback="#"),
        "Server data starts here",
        server_pub_key,
        config["PeerConfig"].get("PeerAllowedIPs", fallback="0.0.0.0/0"),
        "{}:{}".format(
            config["PeerConfig"].get(
                "PublicIP", fallback=config["Server"].get("Address")
            ),
            config["PeerConfig"].get(
                "PublicPort", fallback=config["Server"].get("ListenPort")
            ),
        ),
        config["PeerConfig"].get("PersistentKeepalive", fallback=10),
    )
    # Add for zip file updates
    configs_zip[user] = wg_config
    return (client_pub_key, addr)


def run_command(cmd):
    return_value = (
        subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        .decode("utf-8")
        .strip()
    )
    return return_value


def check_wg_installed():
    try:
        run_command("command wg")
    except:
        raise ValueError(
            "Please install wg (usually wireguard tools) to use this script"
        ) from None


def verify_key(key):
    if len(key) == 0 or re.fullmatch(regex_key, key) == None:
        raise ValueError
    else:
        return


def wireguard_config(config, reset):

    runid = random.randint(0, 100000)

    check_wg_installed()

    check_wireguard_conf(config["General"].get("WiregardConfig"))

    # Set up local state
    d_state = setup_state(config["General"].get("State"))

    # If the network in the config file changed, clear state. We are gonna redo everything
    if (
        reset == True
        or "Network" not in d_state
        or d_state["Network"] != config["General"].get("Network")
    ):
        d_state = {"users": {}, "addrs": {}, "keys": {}}
        d_state["Network"] = config["General"].get("Network")
        pass

    hosts = set(ipaddress.ip_network(config["General"].get("Network")).hosts())
    # Remove the server IP address from contention
    hosts.difference_update(set(config["Server"].get("Address")))

    cidr_mask = ipaddress.ip_network(config["General"].get("Network")).prefixlen

    # The output string that we are creating
    wg_config = "\n".join(server_config).format(
        "{addr}/{mask}".format(addr=config["Server"].get("Address"), mask=cidr_mask),
        config["Server"].getint("ListenPort"),
        config["Server"].get("PrivateKey"),
    )

    try:
        server_pub_key = run_command(
            "echo -n {} | wg pubkey".format(config["Server"].get("PrivateKey"))
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(
            "Could not generate public key for server. Error: {}".format(
                e.output.decode("utf-8").strip()
            )
        ) from None
    # err_print(server_pub_key)

    # First find all the deleted users in the cache
    for user, key in config["Peers"].items():
        if user in d_state["users"]:
            d_state["users"][user]["runid"] = runid
            pass
        pass

    # Remove deleted user objects
    for user in list(d_state["users"].keys()):
        if d_state["users"][user]["runid"] != runid:
            del d_state["addrs"][d_state["users"][user]["Address"]]
            del d_state["keys"][d_state["users"][user]["PublicKey"]]
            del d_state["users"][user]

    # Remove all the live hosts from the address pool
    hosts.difference_update(d_state["addrs"].keys())

    configs_zip = {}

    for user, key in config["Peers"].items():
        if key == "eBnmgBe25RoynALYNIJGGtJawr+2CVzmF4dre7DHzns=":
            raise ValueError(
                "{} is using the example key provided. Please change it to auto or another key using `wg genkey`.".format(
                    user
                )
            )
        if user not in d_state["users"]:
            (client_pub_key, addr) = create_config(
                user,
                key,
                hosts,
                d_state,
                cidr_mask,
                config,
                server_pub_key,
                configs_zip,
                runid
            )

        else:
            try:
                addr = d_state["users"][user]["Address"]
                client_pub_key = d_state["users"][user]["PublicKey"]
            except KeyError:
                try:
                    del d_state["addrs"][d_state["users"][user]["Address"]]
                    del d_state["keys"][d_state["users"][user]["PublicKey"]]
                except:
                    # We don't care
                    pass

                err_print(
                    "Couldn't rebuild from cache for {user}. Regenerating...".format(
                        user=user
                    )
                )
                # In case we don't have something, abandon this cache and build from the config
                d_state["users"][user] = {}
                (client_pub_key, addr) = create_config(
                    user,
                    key,
                    hosts,
                    d_state,
                    cidr_mask,
                    config,
                    server_pub_key,
                    configs_zip,
                )

        wg_config += "\n"
        wg_config += "\n".join(server_peers).format(
            user, client_pub_key, "{}/32".format(addr)
        )

        pass

    with open(config["General"].get("WiregardConfig"), mode="wt") as f:
        f.write("{}\n".format(wg_config))

    json_state = json.dumps(d_state)

    with open(config["General"].get("State"), mode="wt") as f:
        l = f.write(json_state)
        # Maybe check the length, how important is it?

    if len(configs_zip) > 0:
        configsZip = io.BytesIO()
        with zipfile.ZipFile(
            configsZip, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=False
        ) as zipfileptr:
            for user, config in configs_zip.items():
                zipfileptr.writestr("{}.conf".format(user), config)
                pass
            pass

        print("-----START data-uri-----")
        print(
            "data:application/zip;base64,{}".format(
                base64.b64encode(configsZip.getvalue()).decode()
            )
        )
        print("-----FINISH data-uri-----")
        print()
        err_print(
            "1. Go to https://securityriskadvisors.github.io/wireguard_remote_access/download_config"
        )
        err_print(
            "2. Copy the data-uri above (between the -----START----- and -----FINISH----- lines)"
        )
        err_print("3. Follow the instructions on the page to download the configs.")
        err_print()
        err_print(
            "If you don't want to use a third-party site, you can add a bookmarklet from that page, or from below"
        )
        err_print("Drag the below link to your bookmarks bar and click to activate")
        err_print(
            "javascript:(function()%7Bvar%20d%20%3D%20document%3B%0Avar%20od%20%3D%20d.createElement('div')%3B%0Aod.style.cssText%20%3D%20%22position%3A%20fixed%3B%20top%3A%200%3B%20display%3A%20block%3B%20width%3A%20100%25%3B%20height%3A%20100%25%3B%20background-color%3A%20rgba(0%2C0%2C0%2C0.5)%3B%20z-index%3A%20999%3B%22%0Avar%20dd%20%3D%20d.createElement('div')%3B%0Add.style.cssText%20%3D%20%22position%3A%20absolute%3B%20top%3A%2045%25%3B%20left%3A%2045%25%3B%22%3B%0Avar%20i%20%3D%20d.createElement('textarea')%3B%0Ai.placeholder%20%3D%20%22Paste%20data%20uri%20here...%22%3B%0Avar%20s%20%3D%20d.createElement('button')%3B%0As.innerHTML%20%3D%20%22Download%20File%2FClose%22%3B%0As.addEventListener(%22click%22%2C%20function()%20%7B%0Aif%20(i.value%20%3D%3D%20%22%22)%20%7B%20%0Ad.body.removeChild(od)%3B%0Areturn%3B%20%7D%0Al%20%3D%20d.createElement('a')%3B%0Al.download%20%3D%20%22configs.zip%22%3B%0Al.href%20%3D%20i.value%3B%0Al.click()%3B%0Add.appendChild(l)%3B%0Al.click()%3B%0Ad.body.removeChild(od)%3B%0A%7D)%3B%0Add.appendChild(i)%3B%0Add.appendChild(d.createElement('br'))%3B%0Add.appendChild(s)%3B%0Aod.appendChild(dd)%3B%0Ad.body.appendChild(od)%3B%7D)()%3B"
        )
        err_print()
    else:
        err_print("No new configs added")


def restart_service(config, restart):
    # We don't want to restart so let's not even try
    if restart == "no" or restart == "n":
        return

    from pathlib import Path

    wg_int = Path(config["General"].get("WiregardConfig")).stem
    if restart == "a" or restart == "ask":
        while True:
            ui = input(
                "Would you like to restart the wg ({}) service? [Y/n]: ".format(wg_int)
            )
            if ui == "Y" or ui == "y" or ui == "":
                restart = "yes"
                break
            if ui == "n" or ui == "N":
                return
            err_print("Input {} not recognized. Please try again".format(ui))
            pass

        pass
    if restart == "y" or restart == "yes":
        try:
            run_command("systemctl restart wg-quick@{}.service".format(wg_int))
        except subprocess.CalledProcessError as e:
            raise ValueError(
                "Could not restart service. Error: {}".format(
                    e.output.decode("utf-8").strip()
                )
            ) from None

    return


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Generates a wireguard config for users"
    )

    parser.add_argument(
        "--config",
        "-c",
        default=DEFAULT_USERS_CONFIG,
        help="path to the config file. Defaults to: " + DEFAULT_USERS_CONFIG,
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="clear existing cache and regenerate all config files",
    )
    parser.add_argument(
        "--restart-service",
        "-r",
        choices=["yes", "y", "no", "n", "ask", "a"],
        default="ask",
        dest="restart",
        help="restart wireguard service after updating file",
    )

    args = parser.parse_args()

    config = parse_config(config_file=args.config)

    # TODO implement logging which can be updated from main
    wireguard_config(config, args.reset)

    restart_service(config, args.restart)