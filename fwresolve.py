#!/usr/bin/env python3

import ipaddress
import json
import logging
import os
import socket
import subprocess
import sys
import time

CONFIG_PATH = "/etc/fwresolve/config.json"
LOG_PATH = "/var/log/fwresolve.log"
UPDATE_TIME = 7200

NFT_TABLE = "inet"
NFT_FAMILY = "filter"
NFT_CHAIN = "input"
NFT_SET = "hadomains"

HA_SOCK_PATH = "/run/haproxy/admin.sock"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


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


def resolve_domains(domains: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    _domains = list(set(domains))
    for dom in _domains:
        try:
            ip = socket.gethostbyname(dom)
            result[dom] = ip
        except Exception as e:
            logging.warning(msg=f'ip resolve failed for "{dom}": {e}')
    return result


class HAProxy:
    def __init__(self, sock_path="/var/run/haproxy.sock") -> None:
        if not os.path.exists(sock_path):
            raise FileNotFoundError(f"HAProxy sock file not found: {sock_path}")
        self.sock_path = sock_path

    def _send_cmd(self, cmd: str) -> str:
        data = b""
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(self.sock_path)
            s.sendall((cmd + "\n").encode())
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.decode()

    def show_map(self, map_file: str) -> str:
        return self._send_cmd(f"show map {map_file}")

    def add_map_item(self, map_file: str, key: str, value: str):
        return self._send_cmd(f"add map {map_file} {key} {value}")

    def del_map_item(self, map_file: str, key: str):
        return self._send_cmd(f"del map {map_file} {key}")

    def clear_map(self, map_file: str):
        return self._send_cmd(f"clear map {map_file}")

    def bulk_renew_map(self, map_file: str, data: dict[str, str]):
        resp = self._send_cmd(f"prepare map {map_file}")
        if resp == "" or resp.startswith("Unknow"):
            logging.error(
                msg=f"failed to bulk renew map {map_file}: map does not exist"
            )
            return

        cid = resp.split()[-1]

        if not cid.isdigit():
            logging.warning(msg=f"failed to get temp map {map_file} id: {cid}")
            return

        self._send_cmd(f"clear map @{cid} {map_file}")

        for key, val in data.items():
            self._send_cmd(f"add map @{cid} {map_file} {key} {val}")
        resp = self._send_cmd(f"commit map @{cid} {map_file}")
        if len(resp.strip()) > 0:
            logging.warning(msg=f"failed to commit map {map_file}: {resp}")


class HaMap:
    def __init__(self) -> None:
        self.mapfile = ""
        self.domains: list[str] = []
        self.ips: list[str] = []

    def __str__(self) -> str:
        s = (
            "mapfile: "
            + self.mapfile
            + "\n  domains:\n\t"
            + "\n\t".join(self.domains)
            + "\n  ips:\n\t"
            + "\n\t".join(self.ips)
        )
        return s

    @classmethod
    def from_dict(cls, d):
        if not isinstance(d, dict):
            return None
        if not isinstance(d.get("mapfile"), str):
            return None
        hm = HaMap()
        hm.mapfile = d["mapfile"]
        if isinstance(d.get("domains"), list):
            hm.domains = d["domains"]
        if isinstance(d.get("ips"), list):
            for ip in d["ips"]:
                try:
                    ipaddress.ip_address(ip)
                    hm.ips.append(ip)
                except:
                    logging.warning(
                        msg=f'invalid ip address in hm config mapfile "{hm.mapfile}": "{ip}". Skipping'
                    )
        return hm

    def domains_dict(self) -> dict[str, str]:
        domains = {}
        for d in self.domains:
            domains[d] = ""
        return domains


class NftSet:
    domains: list[str] = []
    ips: list[str] = []

    def __init__(self, table: str, family: str, name: str) -> None:
        self.table = table
        self.family = family
        self.name = name

    def __str__(self) -> str:
        return f"table={self.table},family={self.family},name={self.name}"

    def set_domains(self, domains) -> None:
        if isinstance(domains, list):
            self.domains = list(set(domains))

    def set_ips(self, ips) -> None:
        if not isinstance(ips, list):
            return

        self.ips = []
        ips = list(set(ips))
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                self.ips.append(ip)
            except:
                logging.warning(
                    msg=f'invalid ip address in nft set[{self}]: "{ip}". Skipping'
                )

    def update(self, resolved: dict[str, str] = {}):
        ips: list[str] = self.ips.copy()

        for dom in self.domains:
            ip = resolved.get(dom)
            if ip:
                ips.append(ip)

        ips = list(set(ips))

        ruleset = f"""
flush set {self.table} {self.family} {self.name}
add element {self.table} {self.family} {self.name} {{ {", ".join(ips)} }}
"""
        try:
            subprocess.run(["nft", "-f", "-"], input=ruleset.encode(), check=True)
        except subprocess.CalledProcessError as e:
            logging.error(msg=f"nftables set [{self}] update failed: {e}")
        except Exception as e:
            logging.error(msg=f"failed to call nftables on set [{self}] update: {e}")

    @classmethod
    def from_dict(cls, d):
        if not isinstance(d, dict):
            return None

        table = d.get("table")
        family = d.get("family")
        name = d.get("name")

        if not table:
            return None
        if not family:
            return None
        if not name:
            return None

        ns = NftSet(table, family, name)
        ns.set_domains(d.get("domains", []))
        ns.set_ips(d.get("ips", []))
        return ns


class DomainIpUpdater:
    update_time: int
    nft_sets: list[NftSet] = []
    ha_maps: list[HaMap] = []
    ha_nft_set: NftSet | None = None
    ha_sockpath: str
    ha_resolved: dict[str, str] = {}
    nft_resolved: dict[str, str] = {}

    def __init__(self, confpath="") -> None:
        self.load_config(confpath)

    def load_config(self, confpath="") -> None:
        if not confpath:
            confpath = CONFIG_PATH

        cfg_file = read_config_json(confpath)

        if not cfg_file:
            return

        self.update_time = cfg_file.get("updateTime", UPDATE_TIME)
        self.ha_sockpath = cfg_file.get("haSockPath", HA_SOCK_PATH)
        self.ha_nft_set = NftSet(
            table=cfg_file.get("nftTable", NFT_TABLE),
            family=cfg_file.get("nftFamily", NFT_FAMILY),
            name=cfg_file.get("nftSet", NFT_SET),
        )

        if isinstance(cfg_file.get("haMap"), list):
            for item in cfg_file["haMap"]:
                hm = HaMap.from_dict(item)
                if hm is not None:
                    self.ha_maps.append(hm)

        if isinstance(cfg_file.get("nftSetList"), list):
            for item in cfg_file["nftSetList"]:
                ns = NftSet.from_dict(item)
                if ns is not None:
                    ns.set_domains(item.get("domains", []))
                    ns.set_ips(item.get("ips", []))
                    self.nft_sets.append(ns)

        self.ha_resolved = self.resolve_ha_domains()
        self.nft_resolved = self.resolve_nft_domains()

    def __str__(self) -> str:
        s = (
            f"upd_time: {self.update_time}"
            + "\n-- nft:"
            + f"\nset: {self.ha_nft_set}"
            + "\n-- HA:\n"
            + f"ha_sockpath: {self.ha_sockpath}"
            + "\nmaps:"
        )
        for hm in self.ha_maps:
            s += "\n ---" + hm.__str__()
        return s

    def resolve_ha_domains(self) -> dict[str, str]:
        domains = []
        for hm in self.ha_maps:
            domains.extend(hm.domains)
        return resolve_domains(domains)

    def resolve_nft_domains(self) -> dict[str, str]:
        domains = []
        for nft in self.nft_sets:
            domains.extend(nft.domains)
        return resolve_domains(domains)

    def ha_ips_all(self) -> list[str]:
        result: list[str] = []
        result.extend(self.ha_resolved.values())
        for hm in self.ha_maps:
            result.extend(hm.ips)
        return result

    def update_nft(self) -> None:
        ips = self.ha_ips_all()
        if self.ha_nft_set is None:
            logging.error(msg="DomainIpUpdater: update_nft: haproxy nft set is empty")
        else:
            self.ha_nft_set.set_ips(ips)
            self.ha_nft_set.update()

        for nft in self.nft_sets:
            nft.update(self.nft_resolved)

    def update_ha(self) -> None:
        try:
            hap = HAProxy(self.ha_sockpath)
        except Exception as e:
            logging.error(msg=f"failed to update HaProxy: {e}")
            return

        for mp in self.ha_maps:
            ips: dict[str, str] = {}
            for i in mp.ips:
                ips[i] = "ok"
            for d in mp.domains:
                i = self.ha_resolved.get(d, "")
                if i == "":
                    continue
                ips[i] = d
            hap.bulk_renew_map(mp.mapfile, ips)

    def update_all(self):
        self.update_nft()
        self.update_ha()

    def run(self, confpath):
        while True:
            self.load_config(confpath)
            self.update_all()
            time.sleep(self.update_time)


def main():
    har = DomainIpUpdater(CONFIG_PATH)
    if len(sys.argv) > 1:
        if sys.argv[1] == "once":
            har.update_all()
        return

    har.run(CONFIG_PATH)


if __name__ == "__main__":
    main()
