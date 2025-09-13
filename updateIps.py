import json
import logging
import os
import socket
import subprocess

LOG_PATH = "./log.log"
CONFIG_PATH = "./domains.json"

NFT_TABLE = "inet"
NFT_CHAIN = "input"
NFT_SET = "allowedips"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


class HAProxy:
    def __init__(self, sock_path="/var/run/haproxy.sock") -> None:
        if not os.path.exists(sock_path):
            raise FileNotFoundError(f"HAProxy sock file not found: {sock_path}")
        self.sock_path = sock_path

    def _send_cmd(self, cmd: str) -> str:
        with socket.socket(socket.AF_LINK, socket.SOCK_STREAM) as s:
            s.connect(self.sock_path)
            s.sendall((cmd + "\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.decode()

    def show_map(self, map_file: str) -> str:
        return self._send_cmd(f"show map {map_file}")

    def add_map_item(self, map_file: str, key: str, value: str):
        return self._send_cmd(f"set map {map_file} {key} {value}")

    def del_map_item(self, map_file: str, key: str):
        return self._send_cmd(f"del map {map_file} {key}")

    def clear_map(self, map_file: str):
        items = self.show_map(map_file).splitlines()
        for item in items:
            parts = item.split()
            if len(parts) >= 2:
                key = parts[0]
                self.del_map_item(map_file, key)

    def replace_ip_map(self, map_file: str, ip_list: dict[str, list[str]]):
        self.clear_map(map_file)
        for label, ips in ip_list.items():
            for ip in ips:
                self.add_map_item(map_file, ip, label)


def read_config_json(file_path):
    data = {}
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        logging.error(msg=f"failed to read file: {e}")
    except json.JSONDecodeError as e:
        logging.error(msg=f"failed to parse config {e}")
    return data


def resolve_domains(conf) -> dict[str, list[str]]:
    ips: dict[str, list[str]] = {}
    for target, domains in conf["domains"].items():
        t_ips = []
        for dom in set(domains):
            try:
                ip = socket.gethostbyname(dom)
                t_ips.append(ip)
            except Exception as e:
                logging.warning(msg=f'ip resolve failed for "{dom}": {e}')
        if t_ips:
            ips[target] = t_ips
    return ips


def update_nftables(set_name: str, target_ips: dict[str, list[str]]):
    ips = []
    for vals in target_ips.values():
        ips.extend(vals)
    ips = set(ips)
    ruleset = f"""
flush set {NFT_TABLE} filter {set_name}
add element {NFT_TABLE} filter {set_name} {{ {", ".join(ips)} }}
"""
    try:
        subprocess.run(["echo", "-e"], input=ruleset.encode(), check=True)
    except subprocess.CalledProcessError as e:
        logging.error(msg=f"nftables set update failed: {e}")
    except Exception as e:
        logging.error(msg=f"failed to call nftables: {e}")


def main():
    config = read_config_json(CONFIG_PATH)

    if not config:
        return

    ip_list = resolve_domains(config)
    update_nftables(config["nft"]["set"], ip_list)

    try:
        hap = HAProxy()
        hap.replace_ip_map(config["ha"]["mapfile"], ip_list)
    except Exception as e:
        logging.error(msg=f"Failed to update HAProxy: {e}")


if __name__ == "__main__":
    main()
