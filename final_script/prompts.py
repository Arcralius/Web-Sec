import os

file_directory = os.path.abspath(__file__)

file_directory = "/".join(file_directory.split("/")[:-1])


print("\nThere are files that are sus, please run 'python " + file_directory + "/quarantine.py'")