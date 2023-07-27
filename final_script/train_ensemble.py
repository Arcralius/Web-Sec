import pickle
from sklearn import metrics
import datetime
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
import tensorflow as tf

# compiled togeter
# Load the trained models
class Trainer:
    def __init__(self):
        filedir = "."
        self.model_files = {
            "NB": f"{filedir}/model_nb.pkl",
            "XGB": f"{filedir}/model_xgb.pkl",
            "SVM": f"{filedir}/model_svm3.pkl",
            "RF": f"{filedir}/model_rf.pkl"    
        }

        with open(f"{filedir}/labels.pkl", "rb") as f:
            labels = pickle.load(f)

        with open(f"{filedir}/tfidf_vectors.pkl", "rb") as f:
            tfidf_vectors = pickle.load(f)

        # Split the dataset into training and testing sets
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(tfidf_vectors, labels, test_size=0.2, random_state=42)

    def train_svm(self):
        """ Re-train the Support Vector Machine (SVM) classifier """
        X_train, X_test, y_train, y_test = self.X_train, self.X_test, self.y_train, self.y_test
        svm_classifier = SVC(kernel='linear', probability=True)
        svm_classifier.fit(X_train, y_train)
        # Save the trained model for future use
        model_file = "model_svm3.pkl"
        with open(model_file, "wb") as file:
            pickle.dump(svm_classifier, file)
        y_pred = svm_classifier.predict(X_test)
        print(metrics.classification_report(y_test, y_pred))


    def generate_X_stack(self, save=False):
        """ Predicts X_test using the model to get the scores to train the ensembler """
        X_train, X_test, y_train, y_test = self.X_train, self.X_test, self.y_train, self.y_test
        outputs = []
        model_files = self.model_files
        for model_name, model_filepath in model_files.items():
            print(model_name)
            tmp = []
            with open(model_filepath, "rb") as f:
                model = pickle.load(f)
            outputs.append([x[0] for x in model.predict_proba(X_test)])
        X_stack = np.column_stack(outputs)
        y_stack = y_train
        if save:
            with open("X_stack.pkl", "wb") as file:
                pickle.dump(X_stack, file)
            with open("y_stack.pkl", "wb") as file:
                pickle.dump(y_stack, file)
        return X_stack
    
            
    def train_ensembler(self, X_stack, y_stack):
        """ Train the ensembler """
        ensemble = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu', input_shape=(4,)),  # 4 predicitons as input
            tf.keras.layers.Dense(3, activation='softmax')
        ])
        X_stack = np.array(X_stack)
        y_stack = np.array(y_stack)
        print("training")
        # training
        ensemble.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
        ensemble.fit(X_stack, y_stack, epochs=12, validation_split= 3/9)

        ensemble.save('ensembler.h5')
        model_file = "ensembler.pkl"
        with open(model_file, "wb") as file:
            pickle.dump(ensemble, file)


if __name__ == "__main__":
    trainer = Trainer()
    #trainer.train_ensembler(trainer.generate_X_stack(save=True), trainer.y_train)
    with open("X_stack.pkl", "rb") as file:
        X_stack = pickle.load(file)
    trainer.train_ensembler(X_stack, trainer.y_test)
