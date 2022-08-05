import json
import pandas as pd
from ethpector.data.node import NodeProvider
from ethpector.utils import bytes_to_hex

RPC_URL = "http://localhost:8545"  # This must be a archive node
FILE = "ethpector-output/validation_set/validation_summary_600.csv"

dp = NodeProvider(RPC_URL)
df = pd.read_csv(FILE)
blocks = pd.read_csv("data/blocks_date_daily.csv")

blocks["n"] = 1
blocks["n"] = blocks["n"].cumsum()

start = 4_500_000

events = {}
for i, row in blocks[blocks["block_id"] > start].iterrows():
    block = row["block_id"]
    date = row["date"]
    n = row["n"]
    label = (block, n, date)
    print(f"working on block {block} {date}")
    for i, row in df.iterrows():
        adr = row["address"].lower().strip()
        slots = [
            x.strip()
            for x in (row["slots"].split(",") if not pd.isna(row["slots"]) else [])
        ]

        is_deployed = dp.get_code(adr, block_identifier=block) != "0x"
        if not is_deployed:
            continue

        if adr not in events:
            print(f"{adr} deployed at {block}")
            events[adr] = {"slots": {}, "deployed_at": label, "name": row["name"]}

        current = events[adr]

        for slot in slots:
            if slot == "symbolic":
                continue

            if slot not in current["slots"]:
                current["slots"][slot] = []

            sl = current["slots"][slot]

            last = sl[-1] if len(sl) > 0 else (None, None)

            value = bytes_to_hex(dp.get_storage_at(adr, slot, block_identifier=block))

            old_value = last[1]

            if value != old_value:
                print(
                    f"value changed for {adr} on slot {slot} "
                    f"from {old_value} to {value}"
                )
                if int(value, 16) == 0:
                    print(f"Address {adr} is going trustless !!!!!!!")
                sl.append((label, value))


with open("storage_evolution.json", "w") as f:
    json.dump(events, f)


with open("storage_evolution.json", "r") as f:
    events = json.load(f)

    max_time = 0
    for address, changeset in events.items():

        for slot, listofchanges in changeset["slots"].items():
            for change in listofchanges:
                day = change[0][1]
                if day > max_time:
                    max_time = day

    min_time = blocks[blocks["block_id"] > start].iloc[0]["n"]
    print(f"\\draw[|->] ({min_time}, -2) -- ({max_time}, -2); ")

    mtable = ["J", "F", "M", "A", "M", "J", "J", "A", "S", "O", "N", "D"]
    last_m = None
    last_y = None
    for i, row in blocks[blocks["block_id"] > start].iterrows():

        year, month, day = row["date"].split("-")
        if last_m is None:
            last_m = month
        if last_y is None:
            last_y = year
        n = row["n"]
        date = row["date"]

        if year != last_y:
            print(
                f"\\draw[black] ({n}, -2) --++ (0, -8pt) "
                f"node[below] {{{year[2:]}}};"
            )
            last_y = year
        else:
            if month != last_m:
                print(
                    f"\\draw[black] ({n}, -2) --++ (0, -3pt) "
                    f"node[below] {{\\tiny {mtable[int(month)-1]}}};"
                )
                last_m = month

    for i, (address, changeset) in enumerate(events.items()):
        da = changeset["deployed_at"]
        name = changeset["name"].split("(")[0].replace("_", "\\_")
        name = name if len(name) < 30 else name[:30] + " \\dots"
        addr = address[:10]
        deploy_day = da[1]
        print(
            f"\\draw[|-|] ({deploy_day}, {i}) -- ({max_time}, {i}) "
            f"node[right] {{\\tiny {name}}};"
        )

        for slot, listofchanges in changeset["slots"].items():
            for change in listofchanges:
                day = change[0][1]
                value = int(change[1], 16)
                x = "tl" if value == 0 and day != deploy_day else ""
                print(f"\\node[datapoint,{x}]  at ({day}, {i}) {{}}; % {slot} {change}")
