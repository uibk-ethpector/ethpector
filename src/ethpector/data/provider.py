import logging
from functools import lru_cache
from urllib.parse import urlparse
from mythril.ethereum.interface.rpc.client import EthJsonRpc
from .etherscan import EtherscanProvider
from .ipfs import IpfsProvider
from .swarm import SwarmProvider
from .node import NodeProvider
from .signatures import SignatureProvider
from .sourcify import SourcifyProvider
from .base import DataProvider


_logger = logging.getLogger(__name__)


class AggregateProvider(DataProvider):

    """The aggregate provider provides a simple way to query all available
    data-sources for a piece of information. The return value is always a dict
    where keys are the unique name provided by provider_name.
    """

    def __init__(self, config):
        self._config = config
        self._provider = {}
        if not config.offline():
            if config.etherscan_token():
                self._add_provider(EtherscanProvider(config.etherscan_token()))
            if config.rpc_url():
                self._add_provider(NodeProvider(config.rpc_url()))
            self._add_provider(
                SourcifyProvider(config.sourcify_base_url(), config.chain_id())
            )
            self._add_provider(IpfsProvider())
            self._add_provider(SwarmProvider())
        self._add_provider(SignatureProvider(enable_online_lookup=not config.offline()))

        if config.mythril.concolic_exec() and config.rpc_url() is None:
            _logger.warning(
                "Flag concolic needs a RPC/Node url"
                " configured to work properly. Ignoring."
            )

    def _add_provider(self, p):
        self._provider[p.provider_name()] = p

    def _exec(self, func, *args):
        res = {}
        for n, v in self._provider.items():
            try:
                f = getattr(v, func)
                r = f(*args)
                if r:
                    res[n] = r
            except NotImplementedError as e:
                _logger.debug(f"{func} not implemented for " f"dataprovider {n}: {e}")
        return res

    @lru_cache(maxsize=16)
    def function_name(self, *args):
        return self._exec("function_name", *args)

    @lru_cache(maxsize=16)
    def event_name(self, *args):
        return self._exec("event_name", *args)

    @lru_cache(maxsize=16)
    def get_code(self, *args):
        return self._exec("get_code", *args)

    @lru_cache(maxsize=16)
    def get_balance(self, *args):
        return self._exec("get_balance", *args)

    @lru_cache(maxsize=16)
    def address_tag(self, *args):
        return self._exec("address_tag", *args)

    @lru_cache(maxsize=16)
    def source_code(self, *args):
        return self._exec("source_code", *args)

    @lru_cache(maxsize=16)
    def source_abi(self, *args):
        return self._exec("source_abi", *args)

    @lru_cache(maxsize=16)
    def source_metadata(self, *args):
        return self._exec("source_metadata", *args)

    @lru_cache(maxsize=16)
    def provider_name(self):
        return self._exec("provider_name").keys()

    @lru_cache(maxsize=16)
    def get_storage_at(self, *args):
        return self._exec("get_storage_at", *args)

    def get_provider(self, name):
        return self._provider[name] if name in self._provider else None

    def first_of(self, name_list, fail=True):
        if type(name_list) == str:
            name_list = [name_list]
        for x in name_list:
            p = self.get_provider(x)
            if p:
                return p
        if fail:
            raise Exception(
                "None of the selected online data providers is configured: {}".format(
                    name_list
                )
            )
        else:
            _logger.debug(
                "Provider {name_list} requested, none of which are available, "
                "failing gracefully"
            )
            return None

    # TODO: first of names refer to sub classes which is sub optimal
    @lru_cache(maxsize=16)
    def account_summary(self, address):
        provider = self.first_of(["node", "etherscan"], fail=False)
        if provider:
            return provider.account_summary(address)
        else:
            _logger.debug("No provider to get an account summary are available")
            return None

    # TODO: Move somewhere else?
    def get_mythril_rpc_lookup(self):
        if self._config.rpc_url() and self._config.mythril.concolic_exec():
            url = urlparse(self._rpc_url)
            return EthJsonRpc(
                host=url.hostname + url.path, port=url.port, tls=url.scheme == "https"
            )
        else:
            return None
