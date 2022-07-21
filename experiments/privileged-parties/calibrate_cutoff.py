import os
from utils import score_accuracy
import pandas as pd

FOLDER = "validation_set"
COMPUTE = False
CUTOFFS = [
    5,
    10,
    20,
    30,
    40,
    50,
    75,
    100,
    125,
    150,
    175,
    200,
    250,
    300,
    350,
    400,
    500,
    600,
    700,
    800,
]


def clean_output():
    os.system(f"rm ethpector-output/{FOLDER}/*.txt")
    os.system(f"rm ethpector-output/{FOLDER}/*.json")


def run_experiment(cut_off):
    os.system(f"python experiment.py {FOLDER}.json False 15 {cut_off}")


def get_data(cut_off):
    df = pd.read_csv(f"ethpector-output/{FOLDER}/validation_summary_{cut_off}.csv")
    df["nr_owners"] = df["owners"].apply(
        lambda x: len(x.split(",")) if not pd.isna(x) else 0
    )
    df["nr_slots"] = df["slots"].apply(
        lambda x: len(x.split(",")) if not pd.isna(x) else 0
    )
    sumline = df[
        [
            "nr_tp_function",
            "nr_fp_function",
            "nr_fn_function",
            "nr_tp_owner",
            "nr_fp_owner",
            "nr_fn_owner",
        ]
    ].sum(axis=0, numeric_only=True)
    tp = sumline["nr_tp_function"]
    fp = sumline["nr_fp_function"]
    fn = sumline["nr_fn_function"]

    tpo = sumline["nr_tp_owner"]
    fpo = sumline["nr_fp_owner"]
    fno = sumline["nr_fn_owner"]

    (rc, ac, f1) = score_accuracy(tp, fp, fn)
    (rco, aco, f1o) = score_accuracy(tpo, fpo, fno)

    return (
        df["priv_functions"].sum(),
        df["nr_owners"].sum(),
        df["nr_slots"].sum(),
        df["runtime"].mean(),
        df["cov_sym"].mean(),
        f1,
        f1o,
    )


def get_size_cov_scatter(cut_off):
    df = pd.read_csv(f"ethpector-output/{FOLDER}/validation_summary_{cut_off}.csv")

    print(df.groupby("type")["type"].count())

    return "\n".join(
        [
            f"\\node[datapoint,{v[3]}] at ({v[1]},{v[0]}) {{}}; % {v[2]} -- {v[3]}"
            for k, v in df.apply(
                lambda row: (
                    row["cov_sym"],
                    row["bytecode_size"] / 2,
                    row["name"],
                    row["type"],
                ),
                axis=1,
            ).items()
        ]
    )


if COMPUTE:
    for x in CUTOFFS:  # [10, 50, 100, 200, 300, 400, 500, 600]:
        clean_output()
        run_experiment(x)

data = {}
for x in CUTOFFS:
    data[x] = get_data(x)


print(
    {
        k: {
            "priv_functions": v[0],
            "nr_owners": v[1],
            "nr_slots": v[2],
            "runtime": v[3],
            "cov_sym": v[4],
            "f1": v[5],
            "f1o": v[6],
        }
        for k, v in data.items()
    }
)


print(get_size_cov_scatter(600))
