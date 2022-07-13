import glob
import re
import os
import sys
from utils import score_accuracy, load_dict_from_file


def panda_export(folder, files):
    try:
        import pandas as pd
    except ModuleNotFoundError:
        print("#" * 30)
        print("NOTE: canceling pandas and tex export. Please install pandas")
        print("#" * 30)
        return

    # create dataframe
    data1 = {
        "name": [],
        "address": [],
        "is_contract": [],
        "balance": [],
        "code_avail": [],
        "standards": [],
        "implementation": [],
        "cov_sym": [],
        "cov_diss": [],
        "nr_fun": [],
        "nr_log": [],
        "nr_tp_function": [],
        "nr_fp_function": [],
        "nr_fn_function": [],
        "nr_tp_owner": [],
        "nr_fp_owner": [],
        "nr_fn_owner": [],
        "owners": [],
        "slots": [],
        "slot_writes": [],
    }
    df = pd.DataFrame(data1)

    for file_name in files:
        j = load_dict_from_file(file_name)

        name = j["name"]
        address = j["address"]
        is_contract = j["address_summary"]["is_contract"]
        balance = j["address_summary"]["balance"]
        code_avail = j["etherscan_abi_available"]
        standards = ", ".join(j["known_interfaces"])

        implementation = j["proxy_implementation"]
        implementation = implementation[0] if implementation else None

        cov_ass = j["coverage"]["assembly"]
        cov_sym = j["coverage"]["symbolic"]

        nr_fn = len(j["entry_points"])
        nr_logs = len(j["logs"])

        ls = [
            name,
            address,
            is_contract,
            balance,
            code_avail,
            standards,
            implementation,
            cov_sym,
            cov_ass,
            nr_fn,
            nr_logs,
            j["match_score"]["tp"],
            j["match_score"]["fp"],
            j["match_score"]["fn"],
            j["match_score_owners"]["tp"],
            j["match_score_owners"]["fp"],
            j["match_score_owners"]["fn"],
            ", ".join(j["owners"]),
            ", ".join(j["slots"]),
            ", ".join([x["slot"] for x in j["writes_to_slots"]]),
        ]
        row = pd.Series(ls, index=df.columns)
        df = pd.concat([df, row.to_frame().T], axis=0, ignore_index=True)

    def get_type(row):
        intf = row["standards"].lower()
        name = row["name"].lower()
        if "proxy" in intf or "proxy" in name:
            return "proxy"
        elif "721" in intf:
            return "collectibles"
        elif "20" in intf:
            return "token"
        elif "ENS" in intf:
            return "ens"
        elif "exchange" in name:
            return "exchange"
        elif "router" in name:
            return "exchange"
        elif "distributor" in name:
            return "batching"
        elif "gnosis" in name:
            return "multisig"
        else:
            return "unknown"

    df["type"] = df.apply(get_type, axis=1)

    df.to_csv(os.path.join(folder, "validation_summary.csv"), index=False)


def evaluate_results(folder, include_without_source=False):
    files = glob.glob(os.path.join(f"{folder}", "*_summary.json"))
    out = glob.glob(os.path.join(f"{folder}", "*_out.txt"))

    panda_export(folder, files)

    print("ERRORS " + "#" * 20)
    for file_name in out:
        with open(file_name, "r") as file:
            for i, line in enumerate(file):
                if re.search(r"error|critical", line, re.IGNORECASE):
                    print(f"{file_name} at {i}: {line}")

    print("OUTPUT " + "#" * 20)
    tp, fp, fn, tpo, fpo, fno, cs, ca, n = (0, 0, 0, 0, 0, 0, 0, 0, 0)
    o_total = []
    s_total = []
    for file_name in files:
        j = load_dict_from_file(file_name)

        match = j["match_score"]
        match_owners = j["match_score_owners"]
        coverage = j["coverage"]

        owners = j["owners"]
        slots = j["slots"] if "slots" in j else []
        address = j["address"]
        impl_contract = j["proxy_implementation"]
        ki = j["known_interfaces"]
        im = j["eip_mentions_source_code"]
        has_abi = j["etherscan_abi_available"]

        fn_functions = j["functions_fn"]
        fp_functions = j["functions_fp"]

        fn_owners = j["owners_fn"]
        fp_owners = j["owners_fp"]

        o_total += owners
        s_total += slots
        if include_without_source or has_abi is True:
            tp += match["tp"]
            fp += match["fp"]
            fn += match["fn"]
            tpo += match_owners["tp"]
            fpo += match_owners["fp"]
            fno += match_owners["fn"]
            cs += coverage["symbolic"]
            ca += coverage["assembly"]
            n += 1

            print(f"\nFile: {file_name}:")
            print(f" Etherscan ABI: {has_abi}")
            print(f" Address: {address}")
            print(f" Match: {match}")
            print(f" Match owners: {match_owners}")
            print(f" Coverage: {coverage}")
            print(f" Owners: {owners}")
            print(f" Proxy target: {impl_contract}")
            print(f" Slots: {slots}")
            print(f" Delta fp: {fp_functions}")
            print(f" Delta fn: {fn_functions}")
            print(f" Delta fp owners: {fp_owners}")
            print(f" Delta fn owners: {fn_owners}")
            print(f" interfaces: {ki}")
            print(f" SC mentions: {im}")

    precision, recall, f1 = score_accuracy(tp, fp, fn)

    precision_owner, recall_owner, f1_owner = score_accuracy(tpo, fpo, fno)

    print("\n Summary " + "#" * 20)
    if n > 0:
        loo = list(set(o_total))
        soo = list(set(s_total))
        print("\nSummary:")
        print(f" n: {n}")
        print(f" Pre: {precision}")
        print(f" Rec: {recall}")
        print(f" f1: {f1}")
        print(f" Pre owners: {precision_owner}")
        print(f" Rec owners: {recall_owner}")
        print(f" f1 owners: {f1_owner}")
        print(f" avg. cov; sym {cs / n} ass {ca / n}")
        print(f" # owners: {len(loo)}")
        print(f" Owners: {loo}")
        print(f" # slots: {len(soo)}")
        print(f" slots: {soo}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide experiment folder.")
    evaluate_results(sys.argv[1], bool(sys.argv[2]) if len(sys.argv) == 3 else False)
