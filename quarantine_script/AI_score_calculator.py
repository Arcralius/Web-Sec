import json


def generate_ai_scores(input_file, output_file):
    dict_of_scores = {}

    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()

            for line in lines:
                if line.startswith('Benign :') or line.startswith('Malicious :'):
                    line_parts = line.strip().split(':')
                    label = line_parts[0].strip()
                    filename = line_parts[1].strip()
                    file_hash = line_parts[2].strip()
                    dict_of_scores[f"{filename}-{file_hash}"] = 0.0 if label == 'Benign' else 1.0

        with open(output_file, 'w') as f:
            json.dump(dict_of_scores, f, indent=4)

        print("AI scores have been calculated successfully.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


# Example usage
input_path = "../final_script/SCAN_RESULTS/AI_output.txt"
output_path = "quarantined_files/AI-score.json"

generate_ai_scores(input_path, output_path)
