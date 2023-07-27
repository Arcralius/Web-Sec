import pickle
import plotly.express as px
from sklearn import metrics
from tqdm import tqdm
import matplotlib.pyplot as plt
import pandas as pd

import datetime
import os
import numpy as np
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC


# compiled togeter
# Load the trained models
filedir = "."
model_files = {
    "XGB": f"{filedir}/model_xgb.pkl",
    "SVM": f"{filedir}/model_svm3.pkl",
    "RF": f"{filedir}/model_rf.pkl",
    "NB": f"{filedir}/model_nb.pkl"
}

f1_scores = {}
roc_scores = {}

with open(f"{filedir}/X_test.pkl", "rb") as f:
    X_test = pickle.load(f)
with open(f"{filedir}/y_test.pkl", "rb") as f:
    y_test = pickle.load(f)
    
for model_name, model_filepath in model_files.items():
    print(f"{datetime.datetime.now()} Evalutating {model_name}")
    with open(model_filepath, "rb") as f:
        model = pickle.load(f)
    
    y_pred = model.predict(X_test)
    # Confusion matrix
    cm = metrics.confusion_matrix(y_test, y_pred)
    disp = metrics.ConfusionMatrixDisplay(confusion_matrix=cm,
                                        display_labels = ["Benign", "Malicious"])
    disp.plot()
    disp.ax_.set_title(model_name)
    disp.figure_.savefig(f'{filedir}/{model_name}.png',dpi=300)
    f1_scores[model_name] = metrics.f1_score(y_test, y_pred)
    roc_scores[model_name] = metrics.roc_auc_score(y_test, y_pred)

print(f1_scores)
print(roc_scores)
# creating the bar plot
fig = px.bar(pd.DataFrame(roc_scores, index=["ROC Score"]).T,
             labels = {"index" : "Models"},
             y="ROC Score",
             title = "ROC Scores Comparison")
fig.write_image(f"{filedir}/roc_score.png")
