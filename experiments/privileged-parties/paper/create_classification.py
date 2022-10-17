import pandas as pd
import sys
import hashlib
import shelve
from tqdm import tqdm
from ethpector.assembly import Program
from ethpector.classify import (
    ContractClassifier,
)

tqdm.pandas()


def get_hash(stri):
    return hashlib.sha256(stri.encode("utf-8")).hexdigest()


def get_if(db, x):
    item = db.get(x, None)
    return ",".join(sorted([x.interface_name for x in item[0]])) if item else ""


def get_bc(db, x):
    item = db.get(x, None)
    return ",".join(sorted([x.name for x in item[1]])) if item else ""


def get_functions(db, x):
    item = db.get(x, None)
    return ", ".join(sorted(item[2])) if item else ""


# os.chdir("experiments/privileged-parties")

if len(sys.argv) < 2:
    print("please provide creates csv file.")
    sys.exit(1)

C_FILE = sys.argv[1]

RECALC = True
CALC = True

bt = pd.read_csv("data/blocks_date_daily.csv")

cols = [
    "tx_index",
    "from",
    "to",
    "value",
    "input",
    "output",
    "tracetype",
    "calltype",
    "rewardtype",
    "gas_limit",
    "gas_used",
    "subtraces",
    "traceaddress",
    "error",
    "status",
    "traceid",
    "traceindex",
    "txhash",
    "block",
    "blockgroup",
]

print(C_FILE)
em = pd.read_csv(C_FILE, names=cols)
em = em[em["tracetype"] == "create"]
ok = em[em["status"] == 1][["from", "to", "output", "block"]].copy()

ok["code_hash"] = ok["output"].apply(get_hash)
ok["len"] = ok["output"].apply(lambda x: (len(x) - 2) / 2)

# Compute classifications for the code provided
with shelve.open("_interfaces_classification.db") as db:
    if RECALC:
        print("Deleting database")
        for key in db.keys():
            del db[key]

    cc = ContractClassifier()
    if CALC:
        for i, row in tqdm(ok.iterrows(), total=ok.shape[0]):
            has = row["code_hash"]
            code = row["output"]
            adr = row["to"]
            if has not in db:
                p = Program(code, strip_metadata=True)
                kb = cc.find_known_bytecode(code)
                constants = [
                    (x.operand(), x.operand_size())
                    for x in p.get_constants()
                    if x.operand_size() >= 8
                ]
                events = [hex(x[0]) for x in constants if x[1] == 32]
                functions = p.get_functions(online_lookup=True)
                function_names = [k for k, v in functions] if len(functions) > 0 else []

                ki = cc.get_interface_matches(
                    functions=function_names,
                    events=events,
                    constants=[x[0] for x in constants],
                    threshold=0.5,
                )
                nb = cc.find_known_bytecode(p.get_full_bytecode())
                if ki or nb:
                    # breakpoint()
                    ina = [x.interface_name for x in ki]
                    inb = [x.name for x in nb]

                    print(f"{adr} matches {ina} is {inb}")
                    db[has] = (ki, nb, function_names, constants)

    def cat(row):
        tags = []
        bc = row["bc"].lower()
        f = row["interfaces"].lower()
        nf = len(row["functions"].lower().strip()) == 0

        if nf:
            tags.append("nf")

        if "gast" in bc or "gast" in f:
            tags.append("g")

        if "gnosis" in bc or "gnosis" in f:
            tags.append("m")

        if "owner" in f:
            tags.append("o")

        if "proxy" in f:
            tags.append("p")

        if "erc20" in f:
            tags.append("2")

        if "erc721" in f:
            tags.append("7")

        if len(bc) == 0 and len(f) == 0:
            tags.append("u")

        if (len(bc) > 0 or len(f) > 0) and len(tags) == 0:
            tags.append("ot")

        return "-".join(sorted(tags))

    def cat_broad(row):
        tags = []
        bc = row["bc"].lower()
        f = row["interfaces"].lower()
        nf = len(row["functions"].lower().strip()) == 0

        if "gnosis" in bc or "gnosis" in f:
            tags.append("m")

        if "owner" in f:
            tags.append("o")

        if len(bc) == 0 and len(f) == 0 and nf:
            tags.append("u")

        if (len(bc) > 0 or len(f) > 0 or not nf) and len(tags) == 0:
            tags.append("ot")

        return "-".join(sorted(tags))

    ok["interfaces"] = ok["code_hash"].apply(lambda x: get_if(db, x))
    ok["bc"] = ok["code_hash"].apply(lambda x: get_bc(db, x))
    ok["functions"] = ok["code_hash"].apply(lambda x: get_functions(db, x))
    ok["cat"] = ok.apply(cat_broad, axis=1)
    z = ok[
        [
            "block",
            "from",
            "to",
            "cat",
            "interfaces",
            "bc",
            "functions",
            "len",
            "code_hash",
        ]
    ]
    z["date"] = z["block"].apply(lambda b: bt[bt["block_id"] < b].iloc[-1]["date"])

    print("most common in ot")
    ot = z[z["cat"] == "ot"]
    print(f" Total {len(ot)}")
    from collections import Counter

    ctr = Counter(ot["code_hash"])
    abc = pd.DataFrame()
    nr = 0
    kraken_hashes = []
    print(len(ctr))
    for item, count in ctr.most_common():
        x = ot[ot["code_hash"] == item].iloc[0]
        f = x["functions"]
        b = x["bc"]
        i = x["interfaces"]
        le = x["len"]
        if b == "Kraken Forwarder Proxy?!":
            kraken_hashes.append((item, count))
        else:
            if count > 20:
                print(f"{item} accounts for {count} ({count/len(ot)})")
                print(f"{f} {b} {i} {le}")
        nr += count
        pd.concat([abc, x])

    count = sum([c for i, c in kraken_hashes])

    print(f"Kraken forwarder {len(kraken_hashes)} {count} ({count/len(ot)}) ")

    print(f"most common accounted for {nr/len(ot)}")

    abc.to_csv("most_common_ot.csv", index=False)
    z.to_csv("creates_with_interfaces.csv", index=False)

    g = z.drop("functions", axis=1).groupby(["date", "cat"]).agg({"block": ["count"]})
    g = g.reset_index()
    g.columns = g.columns.to_flat_index().map("_".join)
    g = g.reset_index()
    g.columns = ["n", "date", "cat", "count"]
    g = g[["date", "cat", "count"]].set_index("date")

    t = g.pivot_table(
        values="count", index=g.index, columns="cat", aggfunc="first"
    ).fillna(0)

    window = 3

    t = t[["o", "m", "ot", "u"]]
    t_rel_all = t.div(t.sum(axis=1), axis=0)

    print(t_rel_all["u"].mean())

    tx = t.rolling(window).mean().dropna()
    temp = tx.drop("u", axis=1)
    t_rel = temp.div(temp.sum(axis=1), axis=0)

    t_relc = t_rel.cumsum(axis=1)

    print("%", "#" * 70)
    print("% Relative values")
    for col in reversed(t_relc.columns):
        p = "--".join([f"({i},{r[col]})" for i, (d, r) in enumerate(t_relc.iterrows())])
        s = f"% {col}\n\\draw[{col}] {p} -- ({len(tx) - 1}, 0) -- (0,0) -- cycle;"
        print(s)

    print("%", "#" * 70)
    print("% x Axis")

    mtable = [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "June",
        "July",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    ]
    last_m = None
    last_y = None
    for n, (i, row) in enumerate(t_relc.iterrows()):

        year, month, day = i.split("-")
        if last_m is None:
            last_m = month
        if last_y is None:
            last_y = year
        # n = row["n"]
        print(
            f"\\draw[black] ({n}, 0) --++ (0, -3pt) "
            f"node[below] {{\\tiny {int(day)}}};"
        )

        if year != last_y:
            print(
                f"\\draw[black] ({n}, 0) --++ (0, -12pt) "
                f"node[below] {{{year[2:]}}};"
            )
            last_y = year
        else:
            if month != last_m:
                print(
                    f"\\path[black] ({n}, 0) --++ (0, -8pt) "
                    f"node[below] {{{mtable[int(month)-1]}}};"
                )
                last_m = month

    # for i, row in t_rel.iterrows():
    #     path =
    #     print(f"\\draw[{col}] {};")

    t["n"] = 1
    t["n"] = t["n"].cumsum()

    t_rel["n"] = 1
    t_rel["n"] = t_rel["n"].cumsum()

    lt = {"m": "Multi-Sig", "o": "Owner", "ot": "Other", "u": "Unknown"}

    ignore = ["u"]

    print("#" * 70)
    print("Absolute values")
    for x in reversed(t.columns.drop("n")):
        if x in ignore:
            continue
        out = f"% {lt[x]}\n\\draw[{x}]"
        for i, row in t.iterrows():
            val = 0
            for c in reversed(t.columns.drop("n")):
                if x in ignore:
                    continue
                val += row[c]
                if x == c:
                    break

            out += f"({row['n']-1}, {val}) -- node[datapoint] {{}} "

        out += f"({t['n'].max() -1}, 0);"  # -- (0,0) -- cycle;"
        print(out)

    # legend = ""
    # for x in t.columns.drop("n"):
    #     legend+=f"\\draw[{x}] at ()"

    # print(legend)

    g.to_csv("creates_per_category.csv")
