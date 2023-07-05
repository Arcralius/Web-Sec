import os
import yara
import threading
import argparse

print("----------------YARA SCAN HAS BEGUN\n")
# Parse command-line arguments
parser = argparse.ArgumentParser(description="Recursive YARA scan on a directory")
parser.add_argument("scan_directory", help="Directory to scan")
args = parser.parse_args()

# Directory to scan
scan_directory = args.scan_directory

# Get the path of the script's directory
script_directory = os.path.dirname(os.path.abspath(__file__))
scan_result_directory = os.path.join(script_directory, "SCAN_RESULTS")
if not os.path.exists(scan_result_directory):
    os.makedirs(scan_result_directory)

# YARA rules file extensions
yara_extensions = (".yara", ".yar")

# Output file path
output_file = os.path.join(scan_result_directory, "YARA_output.txt")
with open(output_file, "w") as f:
    f.write("SCAN REPORT FOR YARA SCAN\n\n")

# Find the YARA rules file with the supported extensions
yara_rules_file = None
for ext in yara_extensions:
    file_path = os.path.join(script_directory, f"rules{ext}")
    if os.path.isfile(file_path):
        yara_rules_file = file_path
        break

# Check if a YARA rules file was found
if yara_rules_file is None:
    raise FileNotFoundError("YARA rules file not found")

# Compile the YARA rules
rules = yara.compile(filepath=yara_rules_file)

# Function to scan a file using YARA rules
def scan_file(file_path):
    try:
        matches = rules.match(filepath=file_path)
        file_name = file_path.split("/")[-1]
        if matches:
            with open(output_file, "a") as f:
                print(f"Match found in: {file_name}")
                f.write(f"Match found in: {file_name}\n")
                for match in matches:
                    print(f"Rule: {match.rule}")
                    f.write(f"Rule: {match.rule}\n")
                    if 'description' in match.meta:
                        print(f"Description: {match.meta['description']}")
                        f.write(f"Description: {match.meta['description']}\n\n\n")
        else:
            print(f"No match found in: {file_name}")
    except Exception as e:
        print(f"Error scanning file: {file_path}\n{e}")

# Function to process files in a directory using threads
def process_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path)

# Create a list of threads
threads = []

# Recursively scan the directory using threads
for root, dirs, files in os.walk(scan_directory):
    for directory in dirs:
        directory_path = os.path.join(root, directory)
        thread = threading.Thread(target=process_directory, args=(directory_path,))
        threads.append(thread)
        thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

print("----------------YARA SCAN IS COMPLETED\n\n\n\n\n")