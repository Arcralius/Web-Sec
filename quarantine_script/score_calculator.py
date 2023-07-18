import os
import json
import hashlib


def calculate_sha1(file_path):
    # Open the file in binary mode and calculate the SHA-1 hash
    with open(file_path, 'rb') as file:
        sha1_hash = hashlib.sha1()
        while True:
            data = file.read(65536)  # Read the file in chunks of 64KB
            if not data:
                break
            sha1_hash.update(data)

    return sha1_hash.hexdigest()


def scan_directory(directory, config_file):
    dict_of_scores = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".json"):
                try:
                    with open(file_path, "r") as f:
                        json_data = json.load(f)
                        undetected = json_data[0]["data"]["attributes"]["stats"]["undetected"]
                        malicious = json_data[0]["data"]["attributes"]["stats"]["malicious"]
                        filename = os.path.basename(json_data[1])
                        # Simple score generator
                        try:
                            score = malicious/undetected
                        except ZeroDivisionError:
                            if malicious == 0:
                                score = 0
                            else:
                                score = 1
                        dict_of_scores[f"{filename}-{calculate_sha1(json_data[1])}"] = score
                except json.JSONDecodeError:
                    print(f"Invalid JSON file: {file_path}")
        with open(config_file, "a") as f:
            json.dump(dict_of_scores, f, indent=4)


def create_json_file(filename):
    directory = "./quarantined_files"
    if not os.path.exists(directory):
        os.makedirs(directory)
    file_path = os.path.join(directory, filename)
    with open(file_path, "w") as f:
        pass
    return file_path


# Example usage
VT_config_path = create_json_file("VT-score.json")

directory_path = "../final_script/SCAN_RESULTS/VT_output"
scan_directory(directory_path, VT_config_path)
