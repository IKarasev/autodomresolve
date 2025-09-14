import ipaddress
import json
import logging
import socket
import subprocess
import sys

CONFIG_PATH = "./config.json"
LOG_PATH = "./log.log"
UPDATE_TIME = 600

NFT_TABLE = "inet"
NFT_FAMILY = "filter"
NFT_CHAIN = "input"
NFT_SET = "haset"

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


class HaResolve:
    update_time: int
    ha_maps: list[HaMap] = []
    ha_sockpath: str
    nft_set: str
    nft_table: str
    nft_family: str
    nft_chain: str
    resolved: dict[str, str] = {}

    def __init__(self, confpath="") -> None:
        if not confpath:
            confpath = CONFIG_PATH

        cfg_file = read_config_json(confpath)

        if not cfg_file:
            return

        self.update_time = cfg_file.get("updateTime", UPDATE_TIME)
        self.nft_set = cfg_file.get("nftSet", NFT_SET)
        self.nft_table = cfg_file.get("nftTable", NFT_TABLE)
        self.nft_family = cfg_file.get("nftFamily", NFT_FAMILY)
        # self.nft_chain = cfg_file.get("nftChain", NFT_CHAIN)

        if isinstance(cfg_file.get("haMap"), list):
            for item in cfg_file["haMap"]:
                hm = HaMap.from_dict(item)
                if hm is not None:
                    self.ha_maps.append(hm)

        self.resolved = self.resolve_domains()

    def __str__(self) -> str:
        s = (
            f"upd_time: {self.update_time}"
            + "\n-- nft:"
            + "\nset: "
            + self.nft_set
            + "\ntable: "
            + self.nft_table
            + "\nchain: "
            + self.nft_chain
            + "\n-- HA:\n"
            + f"ha_sockpath: {self.ha_sockpath}"
            + "\nmaps:"
        )
        for hm in self.ha_maps:
            s += "\n ---" + hm.__str__()
        return s

    def resolve_domains(self) -> dict[str, str]:
        result: dict[str, str] = {}
        domains = []
        for hm in self.ha_maps:
            domains.extend(hm.domains)
        domains = list(set(domains))
        for dom in domains:
            try:
                ip = socket.gethostbyname(dom)
                result[dom] = ip
            except Exception as e:
                logging.warning(msg=f'ip resolve failed for "{dom}": {e}')
        return result

    def unique_ips(self) -> list[str]:
        result: list[str] = []
        result.extend(self.resolved.values())
        for hm in self.ha_maps:
            result.extend(hm.ips)
        result = list(set(result))
        return result

    def update_nft_set(self) -> None:
        ips = self.unique_ips()
        ruleset = f"""
flush set {self.nft_table} {self.nft_family} {self.nft_set}
add element {self.nft_table} {self.nft_family} {self.nft_set} {{ {", ".join(ips)} }}
"""
        try:
            subprocess.run(["nft", "-f", "-"], input=ruleset.encode(), check=True)
        except subprocess.CalledProcessError as e:
            logging.error(msg=f"nftables set update failed: {e}")
        except Exception as e:
            logging.error(msg=f"failed to call nftables: {e}")


if __name__ == "__main__":
    har = HaResolve(CONFIG_PATH)
    if len(sys.argv) > 1:
        if sys.argv[1] == "once":
            pass
    else:
        har.update_nft_set()
