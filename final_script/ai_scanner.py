import argparse
import hashlib
import os
import pickle
import threading

print("----------------AI SCAN HAS BEGUN\n")
scan_result_directory = os.path.dirname(os.path.abspath(__file__))

# Output file path
scan_result_directory = os.path.join(scan_result_directory, "SCAN_RESULTS")
if not os.path.exists(scan_result_directory):
    os.makedirs(scan_result_directory)
svm_output_file = os.path.join(scan_result_directory, "svm_output.txt")
with open(svm_output_file, "w") as f:
    f.write("SCAN REPORT FOR SVM SCAN\n\n")
xgb_output_file = os.path.join(scan_result_directory, "xgb_output.txt")
with open(xgb_output_file, "w") as f:
    f.write("SCAN REPORT FOR XGB SCAN\n\n")
nb_output_file = os.path.join(scan_result_directory, "nb_output.txt")
with open(nb_output_file, "w") as f:
    f.write("SCAN REPORT FOR NB SCAN\n\n")
    nb_output_file = os.path.join(scan_result_directory, "nb_output.txt")
rf_output_file = os.path.join(scan_result_directory, "rf_output.txt")
with open(rf_output_file, "w") as f:
    f.write("SCAN REPORT FOR RF SCAN\n\n")


class JSAnalyzerThread(threading.Thread):
    def __init__(self, js_file, model, vectorizer, model_name):
        threading.Thread.__init__(self)
        self.js_file = js_file
        self.model = model
        self.vectorizer = vectorizer
        self.model_name = model_name

    def run(self):
        analyze_js_file(self.js_file, self.model, self.vectorizer, self.model_name)


def calculate_sha1(file_path):
    # Open the file in binary mode and calculate the SHA-1 hash
    with open(file_path, 'rb') as file:
        sha1_hash = hashlib.sha1()
        while True:
            data = file.read(65536)  # Read the file in chunks of 64KB
            if not data:
                break
            sha1_hash.update(data)

    return sha1_hash.hexdigest()


def analyze_js_file(js_file, model, vectorizer, model_name):
    # Read the JavaScript file
    with open(js_file, "r", encoding="latin1") as file:
        code = file.read()
    js_filename = os.path.basename(js_file)

    # Convert the JavaScript code to a TF-IDF vector
    new_vector = vectorizer.transform([code])

    # Make a prediction
    prediction = model.predict(new_vector)
    sha1_hash = calculate_sha1(js_file)

    output_file = os.path.join(scan_result_directory, model_name+"_output.txt")
    with open(output_file, "a") as f:
        if prediction[0] == 1:
            f.write("Malicious : {} : {}\n".format(js_filename, sha1_hash))
            print("The file {} is classified as malicious.".format(js_filename))
        else:
            f.write("Benign : {} : {}\n".format(js_filename, sha1_hash))
            print("The file {} is classified as benign.".format(js_filename))


def analyze_directory(directory):
    print("Start Loading Models...")
    # Load the SVM model
    svm_model_file = "./ai_model/model_svm.pkl"
    with open(svm_model_file, "rb") as file:
        svm_model = pickle.load(file)

    # Load the XGB model
    xgb_model_file = "./ai_model/model_xgb.pkl"
    with open(xgb_model_file, "rb") as file:
        xgb_model = pickle.load(file)

    # Load the NB model
    nb_model_file = "./ai_model/model_nb.pkl"
    with open(nb_model_file, "rb") as file:
        nb_model = pickle.load(file)

    # Load the RF model
    rf_model_file = "./ai_model/model_rf.pkl"
    with open(rf_model_file, "rb") as file:
        rf_model = pickle.load(file)

    # Load or recreate the vectorizer
    vectorizer_file = "./ai_model/vectorizer.pkl"
    with open(vectorizer_file, "rb") as file:
        vectorizer = pickle.load(file)
    print("Done Loading")

    threads = []
    print("-------------Starting SVM model------------")
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".js"):
                js_file = os.path.join(root, file)
                thread = JSAnalyzerThread(js_file, svm_model, vectorizer, "svm")
                thread.start()
                threads.append(thread)
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    threads = []
    print("-------------Starting XGB model------------")
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".js"):
                js_file = os.path.join(root, file)
                thread = JSAnalyzerThread(js_file, xgb_model, vectorizer, "xgb")
                thread.start()
                threads.append(thread)
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    threads = []
    print("-------------Starting NB model------------")
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".js"):
                js_file = os.path.join(root, file)
                thread = JSAnalyzerThread(js_file, nb_model, vectorizer, "nb")
                thread.start()
                threads.append(thread)
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    threads = []
    print("-------------Starting RF model------------")
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".js"):
                js_file = os.path.join(root, file)
                thread = JSAnalyzerThread(js_file, rf_model, vectorizer, "rf")
                thread.start()
                threads.append(thread)
    # Wait for all threads to complete
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze JavaScript files for malicious code.")
    parser.add_argument("directory", type=str, help="Path to the directory")
    args = parser.parse_args()

    analyze_directory(args.directory)
    print("----------------AI SCAN IS COMPLETED\n\n")
