import json


def score_accuracy(tp, fp, fn):
    precision = (tp / (tp + fp)) if (tp + fp) != 0 else 1
    recall = (tp / (tp + fn)) if (tp + fn) != 0 else 1
    f1 = (
        2 * ((precision * recall) / (precision + recall))
        if (precision + recall) != 0
        else 0
    )
    return (precision, recall, f1)


def generate_dummy_dataset(description, address_list):
    dataset = {}
    dataset["description"] = description
    dataset["data"] = [[x.lower(), "", [], []] for x in address_list]
    return dataset


def save_dataset_from_addresses(description, address_list, filename):
    dataset = generate_dummy_dataset(description, address_list)
    save_dict_to_file(filename, dataset)


def load_dict_from_file(filename):
    with open(filename, "r") as file:
        return json.load(file)


def save_dict_to_file(filename, data):
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)


def timestamp():
    from datetime import datetime

    format_str = "%d_%m_%Y_%H:%M:%S_%p"
    result = datetime.now().strftime(format_str)
    return result
