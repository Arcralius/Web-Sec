# Before running this script:

1. Install openssl, openssl-devel as well as yara with the following commands:
sudo apt update
sudo apt install openssl openssl-devel yara

2. Install python requirements 
pip3 install -r requirements.txt

# To run this script:
package-version is optional, if left blank, latest version will be used

- If running pure python script:
python3 fetch.py install <package-name>@<package-version>

- If running as a shell script:
./npm-wrapper.sh install <package-name>@<package-version>
