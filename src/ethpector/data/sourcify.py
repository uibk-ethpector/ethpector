import requests
import logging
from ethpector.data.base import DataProvider, cache

log = logging.getLogger(__name__)


class SourcifyProvider(DataProvider):

    """Provides source-code from the distributed source-code verification
    service sourcify.
    """

    def __init__(self, base_url, chain_id):
        self._base_url = base_url if base_url.endswith("/") else f"{base_url}/"
        self._chain_id = chain_id

    def get_metadata(self, address):
        return self.get_file(address, "metadata.json")

    def get_common_query_str(self, address):
        return (
            f"{self._base_url}server"
            f"/repository/contracts/full_match/{self._chain_id}/{address}/"
        )

    # @cache.memoize(ignore=[0])
    # def get_files(self, address):
    #     r = requests.get(f"{self._base_url}files/tree/{self.chain_id}/{address}")
    #     r.raise_for_status()
    #     if r.status_code == 404:
    #         return None
    #     else:

    #         res = r.json()
    #         log.error(res)
    #         return res

    @cache.memoize(ignore=[0])
    def get_file(self, address, filename, json=True):
        r = requests.get(f"{self.get_common_query_str(address)}{filename}")
        if r.status_code == 404:
            return None
        else:
            r.raise_for_status()
            res = r.json() if json else r.text
            return res

    def source_metadata(self, address):
        sc = self.get_metadata(address)
        if sc:
            if "output" in sc:
                if "abi" in sc["output"]:
                    sc["output"].pop("abi", None)
        return sc

    # def source_code(self, address):
    #     f = self.get_files(address)
    #     if f:
    #         ccs=self.get_common_query_str(address)
    #         tofetch = [x.replace(ccs, "") for x in f if not "metadata.json" in x]
    #         return {x:self.get_file(address, x) for x in tofetch}

    def source_code(self, address):
        f = self.get_metadata(address)
        if f and "sources" in f:
            # sources/browser/Stakehavens.sol
            tofetch = [x for x, v in f["sources"].items() if "metadata.json" not in x]
            return [
                {
                    "file": x,
                    "source_code": self.get_file(address, f"sources/{x}", json=False),
                }
                for x in tofetch
            ]

    def source_abi(self, address):
        sc = self.get_metadata(address)
        if sc:
            if "output" in sc:
                if "abi" in sc["output"]:
                    return sc["output"]["abi"]
        return sc

    def provider_name(self):
        return "sourcify"
