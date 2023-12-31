import linecache
import zipfile
import os

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

# Example usage
file_path = 'test.conf'  # Replace with the path to your file

lines = count_lines(file_path)

if lines > 1:
    x = 2
    while x != lines + 1:
        print(get_line_by_index(file_path, x))
        x = x + 1
