import requests
import sys
import re
import os
import tarfile
import shutil
import tempfile
import subprocess
import hashlib
import json
import zipfile

# CONSTANTS
REGISTRY = "http://localhost:4873/"
# Get the directory of the currently running script
script_directory = os.path.dirname(os.path.abspath(__file__))
scan_results_directory = os.path.join(script_directory, "SCAN_RESULTS")
if not os.path.exists(scan_results_directory):
    os.makedirs(scan_results_directory)
QUARANTINE_FOLDER = "./quarantined_files/"
VT_SCORE = "./SCAN_RESULTS/VT-score.json"
VT_OUTPUT = "./SCAN_RESULTS/VT_output/"
if not os.path.exists(VT_OUTPUT):
    os.makedirs(VT_OUTPUT)
SCORES_DIRECTORY = os.path.join(script_directory, "SCAN_SCORES")
if not os.path.exists(SCORES_DIRECTORY):
    os.makedirs(SCORES_DIRECTORY)
VT_SCORE = os.path.join(SCORES_DIRECTORY, "VT-score.json")
YARA_SCORE = os.path.join(SCORES_DIRECTORY, "yara-score.json")
AI_SCORE = os.path.join(SCORES_DIRECTORY, "AI-score.json")
SVM_SCORE = os.path.join(SCORES_DIRECTORY, "SVM-score.json")
XGB_SCORE = os.path.join(SCORES_DIRECTORY, "XGB-score.json")
NB_SCORE = os.path.join(SCORES_DIRECTORY, "NB-score.json")
RF_SCORE = os.path.join(SCORES_DIRECTORY, "RF-score.json")


# Initialize folders and files needed


def check_npm_install_syntax(command):
    """
    Checks for npm install syntax, for eg.
    npm install lodash
    npm install lodash@14.2.1
    :param command: command received
    :return: tuple of package name(str), then package version(str)
    """
    # Regular expression pattern to match "npm install" command
    pattern = r'^install\s+([\w\-/@]+(?:@[\w\-.]+)?)\s*(?:([\w\-/@]+)(?:\s+[\w\-/@]+)*)*$'

    # Check if the command matches the pattern
    match = re.match(pattern, command)

    if match:
        # Syntax is valid
        package_name = match.group(1)
        print(f"Valid npm install command. Package name: {package_name}")

        # Extract package name and version if available
        package_parts = package_name.split('@')
        if len(package_parts) == 2:
            package_name, package_version = package_parts
            print(f"Package version: {package_version}")
        else:
            print("No package version specified, downloading latest version")
            package_version = None

        return package_name, package_version
    else:
        # Syntax is invalid
        raise Exception("Invalid npm install command syntax")


def calculate_sha1(file_path):
    """
    Calculates SHA-1 hash equivalent of a file
    """
    # Open the file in binary mode and calculate the SHA-1 hash
    with open(file_path, 'rb') as file:
        sha1_hash = hashlib.sha1()
        while True:
            data = file.read(65536)  # Read the file in chunks of 64KB
            if not data:
                break
            sha1_hash.update(data)

    return sha1_hash.hexdigest()


def scan_directory_vt(directory, config_file):
    """
    Scans directory for VirusTotal malicious score
    directory: path to VT_output folder where VT outputs are stored in
    config_file: path to store VT-score.json (VT malicious scoring system)
    """
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


def generate_yara_scores(input_file, output_file):
    dict_of_scores = {}

    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()

            for line in lines:
                if line.startswith('Match found in:'):
                    line_parts = line.strip().split('Match found in: ')
                    filename = line_parts[1].split(' : ')[0]
                    file_hash = line_parts[1].split(' : ')[1].strip('[]')
                    dict_of_scores[f"{filename}-{file_hash}"] = 1.0
                elif line.startswith('No match found in:'):
                    line_parts = line.strip().split('No match found in: ')
                    filename = line_parts[1].split(' : ')[0]
                    file_hash = line_parts[1].split(' : ')[1].strip('[]')
                    dict_of_scores[f"{filename}-{file_hash}"] = 0.0

        with open(output_file, 'w') as f:
            json.dump(dict_of_scores, f, indent=4)

        print("YARA scores have been calculated successfully.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def generate_ai_scores(input_file, output_file):
    dict_of_scores = {}

    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()

            for line in lines:
                if line.startswith('Benign :') or line.startswith('Malicious :'):
                    line_parts = line.strip().split(':')
                    label = line_parts[0].strip()
                    filename = line_parts[1].strip()
                    file_hash = line_parts[2].strip()
                    dict_of_scores[f"{filename}-{file_hash}"] = 0.0 if label == 'Benign' else 1.0

        with open(output_file, 'w') as f:
            json.dump(dict_of_scores, f, indent=4)

        print("AI scores have been calculated successfully.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


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
    """
    Quarantine file based on file_path
    """
    # Create the quarantine folder if it doesn't exist
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

    print(f"File {os.path.basename(file_path)} quarantined in {destination_path}.")


def quarantine_files(dir_path, quarantine_folder):
    counter = 0
    with open(VT_SCORE) as vt_file, open(YARA_SCORE) as yara_file, open(SVM_SCORE) as svm_file, open(XGB_SCORE) as xgb_file\
            , open(NB_SCORE) as nb_file, open(RF_SCORE) as rf_file:
        vt_scores = json.load(vt_file)
        yara_scores = json.load(yara_file)
        svm_scores = json.load(svm_file)
        xgb_scores = json.load(xgb_file)
        nb_scores = json.load(nb_file)
        rf_scores = json.load(rf_file)

    for root, dirs, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_name = os.path.basename(file_path)
            sha1_hash = calculate_sha1(file_path)
            file_identifier = f"{file_name}-{sha1_hash}"

            vt_score = vt_scores.get(file_identifier, 0.0)
            yara_score = yara_scores.get(file_identifier, 0.0)
            svm_score = svm_scores.get(file_identifier, 0.0)
            xgb_score = xgb_scores.get(file_identifier, 0.0)
            nb_score = nb_scores.get(file_identifier, 0.0)
            rf_score = rf_scores.get(file_identifier, 0.0)
            ai_score = svm_score + xgb_score + nb_score + rf_score

            if vt_score > 0.65 or yara_score == 1.0 or ai_score >= 2.0:
                with(open(QUARANTINE_FOLDER+file_name+".txt", "w")) as file:
                    file.write(f"VirusTotal score is: {vt_score}\n")
                    file.write(f"YARA score is: {yara_score}\n")
                    file.write(f"AI model score is: {ai_score}\n")
                quarantine_file(file_path, quarantine_folder)
                counter += 1

    if counter > 0:
        quarantine_config = os.path.join(quarantine_folder, "quarantine.conf")
        with open(quarantine_config, "r+") as file:
            file_content = file.read()
            file.seek(0, 0)
            file.write(str(counter) + "\n" + file_content)


def create_json_file(filename):
    """
    Creates json file based on filename
    filename: name of json file to create
    """
    directory = SCORES_DIRECTORY
    if not os.path.exists(directory):
        os.makedirs(directory)
    file_path = os.path.join(directory, filename)
    with open(file_path, "w") as f:
        pass
    return file_path


def fetch_package(package_name, version=None):
    """
    Fetches package from REGISTRY,
    :param package_name: name of package
    :param version: version of package, if not latest
    :return: url to download npm package(tarball) and version of package
    """
    url = REGISTRY + package_name
    if version:
        url += f"/{version}"
    else:
        url += f"/latest"

    response = requests.get(url)
    if response.status_code == 200:
        package_info = response.json()
        version = package_info["version"]
        tarball_url = package_info["dist"]["tarball"]
        return tarball_url, version
    else:
        return None


def download_package(tarball_url, destination_path):
    """
    Downloads package according to tarball url returned in fetch_package
    :param tarball_url: tarball url returned in fetch_package
    :param destination_path: destination path to download npm package
    :return: True if 200, otherwise False
    """
    response = requests.get(tarball_url)
    if response.status_code == 200:
        with open(destination_path, "wb") as file:
            file.write(response.content)
        return True
    else:
        return False


def extract_npm_package(package_path):
    """
    Extracts npm package(tarball) into temp dir
    :param package_path: path to tarball package
    :return: temp dir with extracted contents
    """
    try:
        # Extract the package contents
        package_dir = os.path.dirname(package_path)
        with tarfile.open(package_path, 'r:gz') as tar:
            tar.extractall(path=package_dir)
    except Exception as e:
        print(f"Failed to extract npm package: {str(e)}")
        return None


def create_temp_dir():
    """
    Create temp file and return path to temp file
    """
    temp_dir = tempfile.mkdtemp()
    return temp_dir


def scan_directory_for_viruses_yara(directory):
    """
    Scan directories recursively with yara_scan.py
    """
    yara_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_scan.py")
    process = subprocess.Popen(['python3', yara_path, directory])
    process.wait()


def scan_directory_for_viruses_ai(directory):
    """
        Scan directories recursively with yara_scan.py
    """
    ai_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_scanner.py")
    process = subprocess.Popen(['python3', ai_path, directory])
    process.wait()


def scan_directory_for_viruses_vt(directory):
    """
        Scan directories recursively with virustotal_api.py
    """
    vt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "virustotal_api.py")
    process = subprocess.Popen(['python3', vt_path, '-d', directory, '-j', VT_OUTPUT])
    process.wait()


def cleanup_temp_directory(directory):
    """
    Clean up temp dir
    :param directory: temp dir
    """
    shutil.rmtree(directory)


def run_cron():
    """
    Run cron.py, a script to warn users about malicious files periodically
    """
    command = ['python3', 'cron.py']
    process = subprocess.Popen(command)
    process.wait()


# Checks npm package syntax
package = check_npm_install_syntax(" ".join(sys.argv[1:]))
package_name, package_version = package
# Fetch package information
tarball_url, package_version = fetch_package(package_name, package_version)
if tarball_url:
    # Set destination path and temporary folder for downloaded package
    extracted_dir = create_temp_dir()
    destination_path = f"{extracted_dir}/{package_name}-{package_version}.tgz"
    # Download the package in temporary folder
    if download_package(tarball_url, destination_path):
        print(f"Successfully downloaded package {package_name}@{package_version}")
        extract_npm_package(destination_path)
        shutil.move(destination_path, destination_path)
        os.remove(destination_path)
        if extracted_dir:
            try:
                # Run different directory scans for viruses
                scan_directory_for_viruses_yara(extracted_dir)
                scan_directory_for_viruses_ai(extracted_dir)
                scan_directory_for_viruses_vt(extracted_dir)
                print(extracted_dir)
                # Create scoring system for VT
                VT_json_path = create_json_file("VT-score.json")
                scan_directory_vt(VT_OUTPUT, VT_json_path)
                # Create scoring system for YARA
                generate_yara_scores(os.path.join(scan_results_directory, 'YARA_output.txt'), os.path.join(SCORES_DIRECTORY, "yara-score.json"))
                # Create scoring system for AI models
                generate_ai_scores(os.path.join(scan_results_directory, 'svm_output.txt'),
                                   os.path.join(SCORES_DIRECTORY, "SVM-score.json"))
                generate_ai_scores(os.path.join(scan_results_directory, 'xgb_output.txt'),
                                   os.path.join(SCORES_DIRECTORY, "XGB-score.json"))
                generate_ai_scores(os.path.join(scan_results_directory, 'nb_output.txt'),
                                   os.path.join(SCORES_DIRECTORY, "NB-score.json"))
                generate_ai_scores(os.path.join(scan_results_directory, 'rf_output.txt'),
                                   os.path.join(SCORES_DIRECTORY, "RF-score.json"))
                # Quarantine based on VT, YARA and AI scoring system
                quarantine_files(extracted_dir, QUARANTINE_FOLDER)
            finally:
                run_cron()
                print("SCRIPT FINISHED")
                print(f"SCAN RESULTS CAN BE FOUND AT {scan_results_directory}")
        else:
            raise Exception("Package extraction failed")
    else:
        print(f"Failed to download package {package_name}@{package_version}")
else:
    print(f"Failed to fetch package {package_name}@{package_version} information")
