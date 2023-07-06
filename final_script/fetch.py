import requests
import sys
import re
import os
import tarfile
import shutil
import tempfile
import subprocess

REGISTRY = "https://registry.npmjs.org/"
# Get the directory of the currently running script
script_directory = os.path.dirname(os.path.abspath(__file__))
scan_results_directory = os.path.join(script_directory, "SCAN_RESULTS")
if not os.path.exists(scan_results_directory):
    os.makedirs(scan_results_directory)


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
        Scan directories recursively with virustotal_apiv2.py
    """
    vt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "virustotal_apiv2.py")
    process = subprocess.Popen(['python3', vt_path, directory])
    process.wait()


def cleanup_temp_directory(directory):
    """
    Clean up temp dir
    :param directory: temp dir
    """
    shutil.rmtree(directory)


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
        if extracted_dir:
            try:
                scan_directory_for_viruses_yara(extracted_dir)
                scan_directory_for_viruses_ai(extracted_dir)
                scan_directory_for_viruses_vt(extracted_dir)
            finally:
                cleanup_temp_directory(extracted_dir)
                print("SCRIPT FINISHED")
                print(f"SCAN RESULTS CAN BE FOUND AT {scan_results_directory}")
        else:
            raise Exception("Package extraction failed")
    else:
        print(f"Failed to download package {package_name}@{package_version}")
else:
    print(f"Failed to fetch package {package_name}@{package_version} information")
