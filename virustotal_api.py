import requests as r
import time
import argparse
import json
import os
from tqdm import tqdm
from multiprocessing.pool import Pool


key = "" # put your virustotal API key in key.txt
with open("key.txt") as f:
    key = f.read()
FILESIZE_LIMIT = 33554432 # 32MB
CUSTOM_FILESIZE_LIMIT = 681574400 #650MB


# VT limits to files of 32MB or less. Need to request a custom URL to allow for up to 650MB.
def get_upload_url():
    """ Gets a custom url to POST the file to.
        Returns the upload url on success, None on failure."""
    x = r.get(r"https://www.virustotal.com/api/v3/files/upload_url", headers = {"x-apikey":key})
    if x.status_code == 200:
        return x.json()['data']
    return None


def upload_file(filepath):
    """ Uploads a file to VT for analysis.
        Returns the report url on success. Exception on failure"""
    # Read the file
    fb = None
    with open(filepath, "rb") as f:
        fb = f.read()
        
    # Check filesize to determine if a custom url is needed
    if len(fb) < FILESIZE_LIMIT:
        url = r"https://www.virustotal.com/api/v3/files"
    elif len(fb) < CUSTOM_FILESIZE_LIMIT:
        url = get_upload_url()
    else:
        raise Exception("File is too big for the API.")
    print("Uploading File to VT api...")
    x = r.post(url,
               headers = {"x-apikey":key},
               files = {"file": ("file.exe", fb)}
               )
    if x.status_code != 200:
        raise Exception(f"{url} returned {x.status_code}")
    link = x.json()['data']['links']['self']
    print(link)
    return link


def get_report(report_url):
    """ Continuously query report_url until their analysis is completed.
        Returns a json on success. """
    while True:
        x = r.get(report_url, headers={'x-apikey':key})
        if x.status_code != 200:
            raise Exception(f"{report_url} returned {x.status_code}")
        report_status = x.json()['data']['attributes']['status']
        if report_status == "completed":
            return x.json()
        print(f"Report is {report_status}...")
        time.sleep(15)


def print_json(report, path):
    """ writes the report to a json """
    if os.path.isdir(path):
        path = os.path.join(path, report['meta']['file_info']['sha1'] + ".json")
    with open(path, "w") as f:
        f.write(json.dumps(report))

        
def print_stats(report):
    """ mainly for my own debugging so its kinda ugly. parses and formats the report from json into a nicer print """
    print("---------- OVERVIEW ----------")
    print("\n".join([f"\t{stat}:{num}" for stat, num in report['data']['attributes']['stats'].items()]))
    for stat,num in report['data']['attributes']['stats'].items():
        if num == 0:
            continue
        print(f"---------- {stat.upper()}({num}) ----------")
        print("\n".join([f"\t{sandbox['engine_name']}" for sandbox in report['data']['attributes']['results'].values() if sandbox['category'] == stat]))

    
def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-f', '--filename', help="Specify single file to upload")
    group.add_argument('-d', '--directory', help="Specify directory of files to upload")
    parser.add_argument('-j', '--json', help="Specify directory for reports to be downloaded to")

    args = parser.parse_args()
    if args.filename:
        x = get_report(upload_file(args.filename))
        #x = get_report(r"https://www.virustotal.com/api/v3/analyses/YmE3MzZlZWEwMDg0MjNiOWYxODEyMTU3YzMxMTk4NWE6MTY4NDgzNDUzMg==")
        print_stats(x)
        if args.json:
            print_json(x, args.json)
    elif args.directory:
        d = args.directory
        if not os.path.exists(d):
            raise Exception("No such directory exists")
        files = [os.path.join(d,f) for f in os.listdir(d)]
        files = [f for f in files if os.path.isfile(f)]
        results = []
        with Pool(10)as pool:
            print("UPLOADING SAMPLES")
            for file in tqdm(files):
                results.append(pool.apply_async(upload_file, args=(file,),))
                #results.append(pool.apply_async(get_report, args=(r"https://www.virustotal.com/api/v3/analyses/YmE3MzZlZWEwMDg0MjNiOWYxODEyMTU3YzMxMTk4NWE6MTY4NDgzNDUzMg==",)))
            pool.close()
            pool.join()
            print("GETTING RESPONSES")
            if args.json:
                for res in tqdm(results):
                    print_json(get_report(res.get()), args.json)
                    
                    

if __name__ == "__main__":
    main()
