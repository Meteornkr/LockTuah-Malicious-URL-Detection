from flask import Flask, request, render_template
import numpy as np
from pd_module import rf, main


app = Flask(__name__)

# Define the prediction function using your existing code
def get_prediction_from_url(test_url):
    features_test = main(test_url)
    
    # Ensure feature count matches the trained model
    if len(features_test) != rf.n_features_in_:
        return "Feature count mismatch."
    
    # Reshape and predict
    features_test = np.array(features_test).reshape((1, -1))
    pred = rf.predict(features_test)
    
    # Map the prediction to the correct category
    if pred[0] == "benign":
        return "SAFE"
    elif pred[0] == "defacement":
        return "MALICIOUS"
    elif pred[0] == "phishing":
        return "MALICIOUS"
    elif pred[0] == "malware":
        return "MALICIOUS"
    else:
        return "UNKNOWN"

# Route for the home page
@app.route('/')
def home():
    return render_template('index.html')

# Route for handling the prediction request
@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    prediction = get_prediction_from_url(url)
    return render_template('index.html', prediction=prediction, url=url)

if __name__ == '__main__':
    app.run(debug=True)
