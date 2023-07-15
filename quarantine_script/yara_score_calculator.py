import json


def generate_yara_scores(input_file, output_file):
    dict_of_scores = {}

    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()

            for line in lines:
                if line.startswith('Match found in:'):
                    line_parts = line.strip().split('Match found in: ')
                    filename = line_parts[1].split(' : ')[0]
                    file_hash = line_parts[1].split(' : ')[1].strip('[]')
                    dict_of_scores[f"{filename}-{file_hash}"] = 1.0
                elif line.startswith('No match found in:'):
                    line_parts = line.strip().split('No match found in: ')
                    filename = line_parts[1].split(' : ')[0]
                    file_hash = line_parts[1].split(' : ')[1].strip('[]')
                    dict_of_scores[f"{filename}-{file_hash}"] = 0.0

        with open(output_file, 'w') as f:
            json.dump(dict_of_scores, f, indent=4)

        print("YARA scores have been calculated successfully.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


# Example usage
input_path = "../final_script/SCAN_RESULTS/YARA_output.txt"
output_path = "quarantined_files/yara-score.json"

generate_yara_scores(input_path, output_path)
