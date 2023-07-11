import subprocess
import os


def readConf():
    file_path = "./test.conf"  # Replace with the actual file path
    try:
        # Open the file in read mode
        with open(file_path, 'r') as file:
            # Read the contents of the file
            file_contents = file.readline()
            return(file_contents)

    except FileNotFoundError:
        print("File not found.")
    except IOError:
        print("An error occurred while reading the file.")

def pwd():
    file_directory = os.path.dirname(os.path.abspath("./cron.py"))
    current_directory = os.getcwd()
    return current_directory

def createCron(): 
    # Get the directory of the script file
    script_directory = os.path.dirname(os.path.abspath(__file__))

    # Specify the filename of the desired file in the same directory
    desired_file = "prompts.py"  # Replace with the desired filename

    # Set the script path to the desired file path
    desired_file_path = os.path.join(script_directory, desired_file)

    # Set the script file as executable
    subprocess.run(['chmod', '+x', desired_file_path])

    # Get the current user's crontab
    subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE)

    # Schedule the script as a cron job
    cron_command = f"* * * * * python3 {desired_file_path} > /dev/pts/1 \n"
    subprocess.run(['crontab', '-'], input=cron_command, text=True)

def remove_cron_job(job_to_remove):
    # Get the current user's crontab using the 'crontab -l' command
    script_directory = os.path.dirname(os.path.abspath(__file__))
    desired_file_path = os.path.join(script_directory, job_to_remove)
    cron_command = f"* * * * * python3 {desired_file_path}\n"

    try:
        crontab_output = subprocess.check_output(['crontab', '-l']).decode('utf-8')
    except subprocess.CalledProcessError:
        print("Error: Failed to retrieve current user's crontab.")
        return

    # Remove the desired cron job from the crontab output
    modified_crontab = '\n'.join(line for line in crontab_output.splitlines() if job_to_remove not in line)

    # Load the modified crontab using the 'crontab -' command
    try:
        subprocess.check_output(['crontab', '-'], input=modified_crontab.encode('utf-8'))
        print(f"The cron job '{cron_command}' has been removed from the current user's crontab.")
    except subprocess.CalledProcessError:
        print("Error: Failed to update current user's crontab.")

malware = readConf()

if int(malware) > 0:
    createCron()
else: 
    remove_cron_job("prompts.py")
