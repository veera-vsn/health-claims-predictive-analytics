from flask import Flask, render_template, request
import pickle
import numpy as np
import pandas as pd

app = Flask(__name__)

# Load the model we saved earlier
model = pickle.load(open('model.pkl', 'rb'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    # 1. Get data from the HTML form
    # Vhi values "attentiveness to quality" so we ensure data is handled correctly
    features = [float(x) for x in request.form.values()]
    final_features = [np.array(features)]
    
    # 2. Make the prediction
    prediction = model.predict(final_features)
    output = round(prediction[0], 2)

    return render_template('index.html', 
                           prediction_text=f'Estimated Annual Healthcare Cost: €{output}')

if __name__ == "__main__":
    app.run(debug=True)