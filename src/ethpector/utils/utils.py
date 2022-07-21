import io
import time
from web3 import Web3
from itertools import tee
from functools import lru_cache
from contextlib import redirect_stdout, redirect_stderr, contextmanager

# def is_hex_string(string, search=re.compile(r"[^a-f0-9]").search):
#    return not bool(search(strip_0x(string.lower())))


class TimeIt:
    def __init__(self):
        self.start = None
        self.end = None

    def __enter__(self):
        self.start = time.time()

    def get_seconds(self):
        return (
            self.end - self.start if self.end is not None else time.time() - self.start
        )

    def __exit__(self, exc_type, exc_value, traceback):
        self.end = time.time()


@contextmanager
def redirect_output(file_name):
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(out):
        try:
            yield None
        finally:
            with open(file_name, mode="w") as f:
                print(out.getvalue(), file=f)


def parse_address_from_storage(storage_hex):
    storage_hex = strip_0x(storage_hex)
    if storage_hex is not None and len(storage_hex) == 64:
        extracted_address = storage_hex[24:]
        if storage_hex[:24] != "0" * 24:
            # some Accounts seem to encode the address shifted by a byte
            # see OpenSeaWyvernExchangev2
            # 0x7f268357A8c2552623316e2562D90e642bB538E5
            extracted_address_shifted = storage_hex[22:-2]

            if storage_hex[:22] != "0" * 22:
                # there is data in the upper bytes left so, likely not an address
                return ("0x" + storage_hex, False, False)
            else:
                if (
                    extracted_address_shifted.count("0") <= (2 * 8)
                    and storage_hex[-2:] == "00"
                ):
                    # the check above should prevent using things shifted
                    # that are likely not addresses
                    # in particular USD Coin at
                    # 0xa2327a938Febf5FEC13baCFb16Ae10EcBc4cbDCF
                    # the storage slot 0x8 of the master minter encodes
                    # data (0x1) in the upper 12 bit of the storage field
                    # and is otherwise all zero which causes a shift without need
                    return ("0x" + extracted_address_shifted, True, True)

        return ("0x" + extracted_address, True, False)
    else:
        return ("0x" + storage_hex, False, False)


def flat(listoflists):
    return [y for x in listoflists for y in x]


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


def truncate_str(string, length):
    return (string[:length] + "..") if len(string) > length else string


def get_function_selector(hex_str):
    if hex_str is None:
        return None
    hex_str = strip_0x(hex_str)
    if len(hex_str) >= 8:
        return hex_str[:8]
    else:
        return None


def is_max_int(int_value, byte_length):
    return int_value == max_int(byte_length)


def fits_in_bytes(int_value, byte_length):
    return int_value <= max_int(byte_length)


@lru_cache(maxsize=32)
def max_int(byte_length):
    return 2 ** (byte_length * 8) - 1


def strip_function_selector(hex_str):
    if hex_str is None:
        return None
    hex_str = strip_0x(hex_str)
    if len(hex_str) >= 8:
        return hex_str[8:]
    else:
        return None


def hex_str_to_bytes(hex_str):
    return bytes.fromhex(hex_str)


def bytes_to_hex(b):
    r = bytes(b).hex()
    return r if len(r) > 0 else None


def is_hex_string(string):
    return string is not None and string.startswith("0x") and len(string) >= 2


def strip_0x(string):
    if is_hex_string(string):
        return string[2:]
    else:
        return string


def to_int(string):
    if type(string) == int:
        return string

    if is_hex_string(string):
        return int(string, 16)
    else:
        return int(string)


def keccak(text):
    return Web3.keccak(text=text).hex()


def function_sig_to_hash(text):
    return keccak(text=text)[:10]
