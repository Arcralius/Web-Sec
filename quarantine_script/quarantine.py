import os
import hashlib
import zipfile
import json
import shutil

VT_SCORE = "./quarantined_files/VT-score.json"


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


def get_file_hashes(directory):
    """Retrieves a list of SHA1 hashes for files in the specified directory."""
    file_hashes = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            sha1_hash = calculate_sha1(filepath)
            file_hashes.append(sha1_hash + '.json')
    return file_hashes


def quarantine_file(file_path, quarantine_folder):
    # Create the quarantine folder and quarantine config if it doesn't exist
    if not os.path.exists(quarantine_folder):
        os.makedirs(quarantine_folder)
    quarantine_config = os.path.join(quarantine_folder, "quarantine.conf")
    if not os.path.exists(quarantine_config):
        with open(quarantine_config, 'w') as file:
            pass

    # Calculate the SHA-1 hash of the file
    sha1 = calculate_sha1(file_path)

    # Generate the destination path in the quarantine folder using the SHA-1 hash as the file name
    file_name = f"{os.path.basename(file_path)}-{sha1}"
    zip_file_name = f"{file_name}.zip"
    destination_path = os.path.join(quarantine_folder, zip_file_name)

    # Create a new zip file
    with zipfile.ZipFile(destination_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:

        # Add the original file to the zip archive
        zip_file.write(file_path, os.path.basename(file_path))

    # Add entry in config file
    with open(quarantine_config, 'a') as file:
        file.write(os.path.abspath(destination_path) + " " + os.path.abspath("./node_modules") + " " + sha1 + "\n")

    print(f"File {file_path} quarantined in {destination_path}.")


def quarantine_files(dir_path, quarantine_folder):
    counter = 0
    with open(VT_SCORE) as file:
        json_data = json.load(file)
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_name = os.path.basename(file_path)
            file_name = file_name + "-" +calculate_sha1(file_path)
            for key, value in json_data.items():
                if file_name == key and value > 0.65:
                    counter = counter+1
                    quarantine_file(file_path, quarantine_folder)
    if counter > 0:
        with open(os.path.join(quarantine_folder, "quarantine.conf"), "r+") as file:
            file_content = file.read()
            file.seek(0, 0)
            file.write(str(counter) + "\n" + file_content)


dir_to_quarantine = "../Yara-Module"
file_to_quarantine = "../Yara-Module/malware1.js"
quarantine_folder = "../final_script/quarantined_files/"

hashes = get_file_hashes(dir_to_quarantine)

quarantine_files(dir_to_quarantine, quarantine_folder)
