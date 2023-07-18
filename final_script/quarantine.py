import linecache
import zipfile
import os
import subprocess

def get_line_by_index(file_path, line_index):
    line = linecache.getline(file_path, line_index)
    return line.strip()

def count_lines(file_path):
    line_count = 0
    with open(file_path, 'r') as file:
        for line in file:
            line_count += 1
    return line_count

def ask_yes_no_prompt(filename):
    while True:
        user_input = input("Do you want to still install "+ filename +"? (Y or N) : ").strip().upper()
        if user_input == "Y":
            return True
        elif user_input == "N":
            return False
        else:
            print("Invalid input. Please try again.")

def print_file_contents(file_path):
    with open(file_path, 'r') as file:
        contents = file.read()
        print(contents)

def split(line):
    word_list = line.split()
    return word_list

def get_last_string_before_slash(text):
    last_string = text.rsplit('/', 1)[-1][:-4]
    return last_string

def unzip_file(zip_file_path, destination_path):
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(destination_path)

def delete_file(file_path):
    try:
        os.remove(file_path)
    except OSError as e:
        print(f"Error: Failed to delete the file '{file_path}'. {e}")

def remove_line_from_file(file_path, line_number):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    if line_number < 1 or line_number > len(lines):
        print(f"Error: Invalid line number '{line_number}'.")
        return

    del lines[line_number - 1]

    with open(file_path, 'w') as file:
        file.writelines(lines)

    print(f"Log file has been updated.")

def update_first_line(file_path, new_content):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    lines[0] = new_content + '\n'

    with open(file_path, 'w') as file:
        file.writelines(lines)

    print(f"Log count updated.")

def append_to_file(file_path, line):
    with open(file_path, 'a') as file:
        file.write(line + '\n')

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

# Example usage
file_path = file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules.conf") # Replace with the path to your file

lines = count_lines(file_path)

remove_cron_job("prompts.py")



if lines > 1:
    
    x = 2
    while x != lines + 1:
        line_contents = split(get_line_by_index(file_path, x))

        print("Malware Log: ")
        
        print(line_contents[2])
        print_file_contents(line_contents[2])

        print("")

        user_response = ask_yes_no_prompt(get_last_string_before_slash(line_contents[0]))

        print("")

        if user_response:
            unzip_file(line_contents[0], line_contents[1])
            delete_file(line_contents[0])
        else:
            delete_file(line_contents[0])
            print(f"Module " + get_last_string_before_slash(line_contents[0]) + " has been removed.")

        print()

        remove_line_from_file(file_path, x)
        update_first_line(file_path, str(int(lines) - 2))
        x = x + 1
        os.remove(line_contents[2])
