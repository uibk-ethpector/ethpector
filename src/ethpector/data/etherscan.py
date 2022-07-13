import json
import logging
from etherscan import Etherscan
from web3 import Web3
from .base import DataProvider, cache

log = logging.getLogger(__name__)


class EtherscanProvider(DataProvider):

    """Etherscan data-provider. Supports fetching source-code, bytecode,
    ABI files, balances etc. for addresses.
    """

    def __init__(self, etherscan_token):
        self._etherscan = Etherscan(etherscan_token)

    def provider_name(self):
        return "etherscan"

    def get_code(self, address):
        return self._etherscan.get_proxy_code_at(Web3.toChecksumAddress(address))

    def get_balance(self, address):
        return self._etherscan.get_eth_balance(address)

    @cache.memoize(ignore=[0])
    def get_contract_source_code(self, address):
        try:
            src = self._etherscan.get_contract_source_code(address)
            if len(src) >= 1:
                if len(src) > 1:
                    log.warning(
                        "Error etherscan returned more than one source_codes, "
                        "taking first."
                    )
                return src[0]
            else:
                return None
        except AssertionError as e:
            log.error(
                "Error while fetching source_code " "from etherscan: {}".format(e)
            )
            return None

    def source_code(self, address):
        sc = self.get_contract_source_code(address)
        if sc:
            # Etherscan packs files in
            c = sc["SourceCode"]
            # remove additional brackets
            c = c[1:][:-1]
            try:
                source_pack = json.loads(c)

                return [
                    {"file": file, "source_code": content["content"]}
                    for file, content in source_pack["sources"].items()
                ]

            except json.decoder.JSONDecodeError:
                pass

            return [{"file": sc["ContractName"], "source_code": sc["SourceCode"]}]
        else:
            return None

    def source_abi(self, address):
        sc = self.get_contract_source_code(address)
        if sc is not None:
            abi_str = sc["ABI"]
            try:
                return (
                    json.loads(abi_str)
                    if sc and not abi_str == "Contract source code not verified"
                    else None
                )
            except json.decoder.JSONDecodeError as e:
                log.error(
                    "could not parse ABI from etherscan. {} {}".format(e, abi_str)
                )
        return None

    def source_metadata(self, address):
        sc = self.get_contract_source_code(address)
        if sc:
            sc.pop("ABI", None)
            sc.pop("SourceCode", None)
        return sc

    # this override is needed to allow account summaries with etherscan
    def address_tag(self, address):
        return None

    def get_storage_at(self, address, slot):
        return self._etherscan.get_proxy_storage_position_at(
            Web3.toChecksumAddress(address), slot
        )
