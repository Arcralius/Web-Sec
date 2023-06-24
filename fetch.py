import requests
import sys
import re
import os
import tarfile
import shutil
import tempfile

REGISTRY = "https://registry.npmjs.org/"


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
    # Create a temporary directory to extract the package
    temp_dir = tempfile.mkdtemp()

    try:
        # Extract the package contents
        with tarfile.open(package_path, 'r:gz') as tar:
            tar.extractall(path=temp_dir)

        return temp_dir
    except Exception as e:
        print(f"Failed to extract npm package: {str(e)}")
        return None


def scan_directory_for_viruses(directory):
    # Implement your antivirus scanning logic here
    # Iterate through the files in the directory and scan each file for viruses
    # You can use a third-party antivirus library or command-line scanner for this task

    # Example logic:
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            # Perform virus scanning on the file
            # Replace this with your actual antivirus scanning code
            print(f"Scanning file: {file_path}")


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
    # Set destination path for downloaded package
    destination_path = f"{package_name}-{package_version}.tgz"
    # Download the package
    if download_package(tarball_url, destination_path):
        print(f"Successfully downloaded package {package_name}@{package_version}")
        extracted_dir = extract_npm_package(destination_path)
        if extracted_dir:
            try:
                scan_directory_for_viruses(extracted_dir)
            finally:
                cleanup_temp_directory(extracted_dir)
        else:
            raise Exception("Package extraction failed")
    else:
        print(f"Failed to download package {package_name}@{package_version}")
else:
    print(f"Failed to fetch package {package_name}@{package_version} information")
