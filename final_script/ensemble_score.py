import pickle
import numpy as np
from tensorflow.keras.models import load_model as tfk__load_model

class Ensembler:
    def __init__(self):
        """ loads model """
        self.model = tfk__load_model('ensembler.h5')

    def predict(self, scores):
        """ Takes in an array of scores.
            Adds a 'batch size' to it so i can run predict() """
        scores = np.expand_dims(np.array(scores), axis=0)
        return self.model.predict(scores, verbose = False)[0][0]
        
