import os
import hashlib
import requests
import argparse


def read_api_key():
    with open('key.txt', 'r') as key_file:
        api_key = key_file.read().strip()
    return api_key


def calculate_file_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def scan_file(api_key, file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': (file_path, open(file_path, 'rb'))}

    response = requests.post(url, files=files, params=params)
    result = response.json()

    if response.status_code == 200:
        resource = result['resource']
        print(f'File uploaded successfully. Scan ID: {resource}')
        return resource
    else:
        print(f'Error uploading file: {result["verbose_msg"]}')
        return None


def get_scan_report(api_key, resource, file_name, file_hash):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource}

    response = requests.get(url, params=params)
    result = response.json()

    if response.status_code == 200:
        if result['response_code'] == 1:
            positives = result['positives']
            total = result['total']
            print(f'Scan completed. Detection ratio: {positives}/{total}')

            # Append scan report to VT_output.txt
            with open('SCAN_RESULTS/VT_output.txt', 'a') as output_file:
                output_file.write(f'File Name: {file_name}\n')
                output_file.write(f'File Hash: {file_hash}\n')
                output_file.write(f'Detection Ratio: {positives}/{total}\n')
                output_file.write('Scanned Engines:\n')
                for engine, result in result['scans'].items():
                    output_file.write(f'{engine}: {result["result"]}\n')
                output_file.write('\n')
        else:
            print('Scan not finished yet. Please check back later.')
    else:
        print(f'Error retrieving scan report: {result["verbose_msg"]}')


def scan_directory(api_key, directory):
    with open('SCAN_RESULTS/VT_output.txt', 'w') as output_file:
        output_file.write('SCAN REPORT FOR VT SCAN\n\n')

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_name = os.path.basename(file_path)
            file_hash = calculate_file_hash(file_path)

            resource = scan_file(api_key, file_path)
            if resource:
                get_scan_report(api_key, resource, file_name, file_hash)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scan JavaScript files in a directory using VirusTotal API')
    parser.add_argument('directory', help='Directory path to scan recursively')

    args = parser.parse_args()
    directory = args.directory

    api_key = read_api_key()
    
    results_dir = os.path.join(os.getcwd(), 'SCAN_RESULTS')
    os.makedirs(results_dir, exist_ok=True)

    scan_directory(api_key, directory)
