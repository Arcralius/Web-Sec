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
        print(f"The file '{file_path}' has been deleted.")
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

    print(f"Line {line_number} has been removed from the file '{file_path}'.")

def update_first_line(file_path, new_content):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    lines[0] = new_content + '\n'

    with open(file_path, 'w') as file:
        file.writelines(lines)

    print(f"The first line of '{file_path}' has been updated.")

# Example usage
file_path = 'test.conf'  # Replace with the path to your file

lines = count_lines(file_path)

if lines > 1:
    x = 2
    while x != lines + 1:
        line_contents = split(get_line_by_index(file_path, x))
        print(line_contents)
        print_file_contents(line_contents[2])
        user_response = ask_yes_no_prompt(get_last_string_before_slash(line_contents[0]))

        if user_response:
            unzip_file(line_contents[0], line_contents[1])
            delete_file(line_contents[0])
        else:
            delete_file(line_contents[0])

        remove_line_from_file(file_path, x)
        update_first_line(file_path, str(int(lines) - 2))
        x = x + 1
