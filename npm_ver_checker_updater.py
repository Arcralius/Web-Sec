# Check for list of npm packages, outdated npm packages and updates them
import subprocess

def run_npm_ls(directory):
    try:
        # Run 'npm ls' command
        ls_output = subprocess.check_output('npm ls', shell=True, cwd=directory).decode('utf-8')
    except subprocess.CalledProcessError as error:
        print(error.output.decode('utf-8'))

    return ls_output

def npm_check_run_updates(directory):
    try:
        # Run 'npm outdated' command
        subprocess.check_output('npm outdated', shell=True, cwd=directory, stderr=subprocess.DEVNULL).decode('utf-8')

        # If no errors are thrown, no outdated npm packages are detected
        print("There are no outdated npm packages")

        update_output = ""

    except subprocess.CalledProcessError as error:
        # If outdated packages are detected python will throw an error
        print("Outdated npm packages:")
        print(error.output.decode('utf-8') + "\n\n")

        # Only run 'npm update' if there are outdated packages
        try:
            print("updating outdated packages...")
            update_output = subprocess.check_output('npm update', shell=True, cwd=directory).decode('utf-8')
            print("Done!")
        except subprocess.CalledProcessError as update_error:
            print("Error occurred during 'npm update':")
            print(update_error.output.decode('utf-8'))
            update_output = ""

    return update_output


# Modify this to node_packages directory
directory = r"C:\Downloads\node_packages"

# List npm modules
ls_output = run_npm_ls(directory)
if len(ls_output.strip()) == 0:
    print("npm ls: No output found.")
else:
    print("List of npm packages:")
    print(ls_output)

# Check for updates, install updates and print updated packages if any
result = npm_check_run_updates(directory)
if result:
    update_output = result

    if len(update_output.strip()) != 0:
        print("npm update:")
        print(update_output)
