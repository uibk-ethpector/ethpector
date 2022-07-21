from multiprocessing import Pool
from extract import analyze_address_multiprocessing
from evaluate import evaluate_results
from utils import (
    save_dataset_from_addresses,
    load_dict_from_file,
    generate_dummy_dataset,
)
from ethpector.utils import flat
import os
import sys


def prepare_worklist(dataset, folder, cutoff_time):
    addresses = [(x[0], x[1], x[2], x[3]) for x in dataset["data"]]
    return [
        (adr, name, expected_res_functions, expected_res_owners, folder, cutoff_time)
        for adr, name, expected_res_functions, expected_res_owners in addresses
    ]


def run_result(seed_file, recursiv, n_parallel, cutoff_time):
    filename = seed_file
    jdata = load_dict_from_file(filename)

    print(f"Input is {filename}: {jdata['description']}")

    clean_filename = filename.split(".")[0]
    rec_lbl = "_rec" if recursiv else ""
    folder = f"ethpector-output/{clean_filename}{rec_lbl}"

    print(f"Results are written to folder {folder}")

    os.makedirs(folder, exist_ok=True)

    worklist = prepare_worklist(jdata, folder, cutoff_time)
    already_seen = {adr.lower(): True for adr, _, _, _, _, _ in worklist}
    owners = set()
    round = 0

    while len(worklist) > 0:
        print(
            f"Executing round {round}, "
            f"worklist length: {len(worklist)}, "
            f"recursiv {recursiv} on {n_parallel} processes "
            f"and a cut off for execution of {cutoff_time} s"
        )
        with Pool(processes=n_parallel, maxtasksperchild=1) as pool:
            return_values = pool.map(analyze_address_multiprocessing, worklist)
        so = [x.lower() for x in flat(return_values)]
        worklist = prepare_worklist(
            generate_dummy_dataset(
                f"{filename} round {round}", [x for x in so if x not in already_seen]
            ),
            folder,
            cutoff_time,
        )
        for x in so:
            already_seen[x] = True

        owners |= set(so)
        round += 1

        if not recursiv:
            break

    save_dataset_from_addresses(
        f"owners of addresses in {filename}",
        list(owners),
        os.path.join(folder, f"{clean_filename}_owners.json"),
    )

    evaluate_results(folder, cutoff_time=cutoff_time)

    # i guess in the last 30 days but not known.
    # https://ethgasstation.info/json/gasguzz.json

    # from analysis import analyze_address
    # analyze_address("0xB80216D5b4eec2BEc74eF10e5d3814Fec6Fd8af0", "UNKNOWN")
    # analyze_address("0xa5409ec958C83C3f309868babACA7c86DCB077c1", "OpenSeaRegistry")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Please provide seed file.")
    run_result(
        seed_file=sys.argv[1],
        recursiv=sys.argv[2].lower() == "true" if len(sys.argv) >= 3 else False,
        n_parallel=int(sys.argv[3]) if len(sys.argv) >= 4 else 8,
        cutoff_time=int(sys.argv[4]) if len(sys.argv) >= 5 else 600,
    )
