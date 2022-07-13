def fetch():
    """Fetches the ethgasstation top gas guzzlers"""
    import requests
    from utils import load_dict_from_file, save_dict_to_file, timestamp

    # Top 10 ETH Contracts By Transaction Count Over Last 1,500 Blocks
    ret = requests.get("https://ethgasstation.info/json/gasguzz.json")

    tags = load_dict_from_file("tags.json")

    ts = timestamp().replace(":", "-")

    dataset = {}
    dataset["description"] = (f"Gas Guzzlers form ethgasstation at {ts}",)
    dataset["data"] = [
        [
            x["to_address"].lower(),
            tags.get(x["to_address"].lower(), ""),
            [],
            [],
            x["gasused"],
            x["pcttot"],
        ]
        for x in ret.json()
    ]

    save_dict_to_file(f"ethgasstation-top-100-gas-users_{ts}.json", dataset)

    # save_dataset_from_addresses(
    #     f"Gas Guzzlers form ethgasstation at {timestamp()}",
    #     [x["to_address"] for x in ret.json()],
    #     "ethgasstation-top-100-gas-users.json",
    # )


if __name__ == "__main__":
    fetch()
