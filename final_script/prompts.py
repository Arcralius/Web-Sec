import os

file_directory = os.path.abspath(__file__)

file_directory = "/".join(file_directory.split("/")[:-1])


print("\nThere are NPM packages that are deemed suspicious, please run 'python3 or python " + file_directory + "/quarantine.py'")