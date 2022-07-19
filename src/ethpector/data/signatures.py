import requests
import logging
from mythril.support.signatures import SignatureDB
from ethpector.data.base import DataProvider, cache
from ethpector.classify.parser import FunctionDefinition
from ethpector.utils import strip_0x

logger = logging.getLogger(__name__)


def add_to_signature_db(signature_str: str):
    """Allows to add new function signatures to the local
    Mythril db.

    Args:
        signature_str (str): String representation of the signature
        as supported by the FunctionDefinition type.
    """
    db = SignatureDB(enable_online_lookup=False)
    try:
        func = FunctionDefinition(signature_str)
        db.add(func.selector(), func.signature_string())
    except Exception as e:
        logger.error(f"Could not save {signature_str} to db. Because: {e}")


class SignatureProvider(DataProvider):

    """Queries function and event signatures from local and online sources.
    Function signatures are first resolved via mythrils offline db. If
    enable_online_lookup is set to true the 4bytes API is called if a function
    signature is not found.

    Event signatures are directly queried from 4bytes and then stored in a
    local on disk cache.

    Attributes:
        sigdb (TYPE): Description
    """

    def __init__(self, enable_online_lookup=True):
        self._offline = not enable_online_lookup
        self.sigdb = SignatureDB(enable_online_lookup=enable_online_lookup)

    def lookup_function(self, sign):
        return self.sigdb.get(sign)

    def lookup_event(self, sign):
        if self._offline:
            return None
        sign = strip_0x(sign)
        r = requests.get(
            "https://www.4byte.directory"
            f"/api/v1/event-signatures/?hex_signature=0x{sign}",
            params={},
        )
        r.raise_for_status()
        res = r.json()
        res = [x["text_signature"] for x in res["results"] if "text_signature" in x]
        return res if len(res) > 0 else None

    def function_name(self, selector: str) -> str:
        """Get a function signature for a selector.

        Args:
            selector (str): hex-string 4 bytes eg. 0xffffffff

        Returns:
            str: function signature e.g. test266151307()
        """
        return self.lookup_function(selector)

    @cache.memoize(ignore=[0])
    def event_name(self, selector: str) -> str:
        """Get a event signature for a selector:

        Args:
            selector (str): hex-string 32 bytes

        Returns:
            str: Event signature (name with parameter)
        """
        return self.lookup_event(selector)

    def provider_name(self) -> str:
        """Unique identifier of this data-provider

        Returns:
            str: identifier
        """
        return "signatures"
