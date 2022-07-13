import inspect
from diskcache import Cache
from .datatypes import AccountSummary

cache = Cache("ethpector-lookup-cache")


class DataProvider:

    """
    Base class for ethpector data-providers
    """

    def _no_imp(self):
        f = inspect.getframeinfo(inspect.currentframe().f_back).function
        raise NotImplementedError(
            "{} not implemented for this provider {}.".format(f, self.provider_name())
        )

    def __init__(self):
        self._no_imp()

    def function_name(self, sign):
        self._no_imp()

    def event_name(self, sign):
        self._no_imp()

    def get_code(self, address):
        self._no_imp()

    def get_balance(self, address):
        self._no_imp()

    def address_tag(self, address):
        self._no_imp()

    def source_metadata(self, address):
        self._no_imp()

    def source_code(self, address):
        self._no_imp()

    def source_abi(self, address):
        self._no_imp()

    def get_storage_at(self, address, slot):
        self._no_imp()

    def provider_name(self):
        f = inspect.getframeinfo(inspect.currentframe().f_back).function
        raise NotImplementedError("{} not implemented for this provider.".format(f))

    def account_summary(self, address: str) -> AccountSummary:
        """Default implementation to acquire an address summary

        Args:
            address (str): Hex-string of an address.

        Returns:
            AccountSummary: Summary of the account state.
        """
        code = self.get_code(address)
        balance = self.get_balance(address)
        name = self.address_tag(address)
        return AccountSummary(
            is_contract=code and len(code) > 2,
            balance=int(balance) if balance else None,
            ens_name=name,
        )
