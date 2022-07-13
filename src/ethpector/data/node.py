import logging
from web3 import Web3
from web3.exceptions import ContractLogicError
from ethpector.data.base import DataProvider, cache
from ethpector.utils import bytes_to_hex

_logger = logging.getLogger(__name__)


def to_checksum(address):
    try:
        return Web3.toChecksumAddress(address)
    except ValueError:
        return None


class NodeProvider(DataProvider):

    """Uses the Ethereum RPC interface to fetch code, balances, storage state
    etc. for a particular address
    """

    def __init__(self, rpc_url):
        self._w3 = Web3(Web3.HTTPProvider(rpc_url))

    def provider_name(self):
        return "node"

    @cache.memoize(ignore=[0])
    def get_code(self, address):
        a = to_checksum(address)
        return self._w3.toHex(self._w3.eth.get_code(a)) if a else None

    def get_balance(self, address):
        a = to_checksum(address)
        return self._w3.eth.get_balance(a) if a else None

    def address_tag(self, address):
        a = to_checksum(address)
        return self._w3.ens.name(a) if a else None

    def get_storage_at(self, address, slot):
        a = to_checksum(address)
        return self._w3.eth.get_storage_at(a, slot) if a else None

    def get_implementation(self, address: str, additional_storage_slots=[]):
        """
        Calls implementation() on the contract for standardized proxies
        this should return the implementation

        Args:
            address (str): Hex-string address
            additional_storage_slots (list, optional): Description

        Returns:
            object: call result
        """
        selector = "0x5c60da1b"  # the selector of implementation()
        r = None
        try:
            r = self.call(address, selector)
        except Exception as e:
            _logger.error(f"Calling implementation() of {address} failed with: {e}")

        if r is not None:
            r = bytes_to_hex(r)

        if r is None:
            eip_1967_impl = (
                "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
            )
            r = bytes_to_hex(self.get_storage_at(address, eip_1967_impl))

        if r is None or int(r, 16) == 0:
            openzeppelin_impl = (
                "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
            )
            r = bytes_to_hex(self.get_storage_at(address, openzeppelin_impl))

        for slot in additional_storage_slots:
            if r is None or int(r, 16) == 0:
                r = bytes_to_hex(self.get_storage_at(address, slot))
            else:
                break

        return None if r is None or int(r, 16) == 0 else r

    def call(self, address: str, payload: str):
        """
        Calls implementation() on the contract for
        standardized proxies this should return the implementation

        Args:
            address (str): Hex-string of the address
            payload (str): Hex-string of the payload (data-field)

        Returns:
            object: return of the call
        """

        a = to_checksum(address)
        try:
            return self._w3.eth.call(
                {
                    "value": 0,
                    "to": f"{a}",
                    "data": payload,
                }
            )
        except ContractLogicError:
            return None
