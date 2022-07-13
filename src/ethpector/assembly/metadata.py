import re
import cbor2
import logging
from mythril.ethereum import util

BINARY_META_PROTOCOLS = [b"bzzr0", b"bzzr1", b"ipfs"]

log = logging.getLogger(__name__)


class BinaryMetadata:
    def __init__(self, code):
        self.code = code
        self.meta = BinaryMetadata.extract_metadata(code)

    @staticmethod
    def extract_metadata(code):
        # inspired by https://github.com/gsalzer/ethutils/blob/main/ethutils/section.py
        data = util.safe_decode(code) if type(code) == str else code

        if type(code) != str:
            log.error(f"Can't extract metadata from non string code -> {code}")
            return (None, None, None)

        for reg in BINARY_META_PROTOCOLS:
            source_match = re.compile(reg).search(data)
            if source_match:
                s = source_match.start()
                key = source_match[0].decode("ascii")
                for j in range(s, max(s - 100, 0) - 1, -1):
                    try:
                        tail = data[j:]
                        obj = cbor2.loads(tail)
                        encoded_length = int.from_bytes(tail[-2:], "big")
                        if (
                            type(obj) == dict
                            and key in obj
                            and encoded_length == len(tail) - 2
                        ):
                            return (
                                {k: v.hex() for k, v in obj.items()},
                                data[j:],
                                j,
                            )
                    except Exception as e:
                        log.debug(
                            f"Metadata: could not decode metadata at position {j}: {e}"
                        )
                        continue
        return (None, None, None)

    @staticmethod
    def is_metadata_url(url):
        return "bzz" in url or "ipfs" in url

    def code_without_metadata(self):
        if self.meta:
            return util.safe_decode(self.code)[: self.offset()].hex()
        else:
            return self.code

    def offset(self):
        return self.meta[2]

    def bytes(self):
        return self.meta[1]

    def meta_obj(self):
        return self.meta[0]

    def solidity_version(self):
        return self.meta_obj()["solc"] if "solc" in self.meta_obj() else None

    def url(self):
        if self.meta_obj():
            x = [
                x.decode("ascii")
                for x in BINARY_META_PROTOCOLS
                if x.decode("ascii") in self.meta_obj()
            ]
            return "{}://{}".format(x[0], self.meta_obj()[x[0]]) if len(x) > 0 else None
        else:
            None
