from flask import Flask, request, jsonify
from joblib import load
import numpy as np

model = load("model.joblib")
app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    features = data['features']
    input_array = np.array(features).reshape(1, -1)
    prediction = model.predict(input_array)
    return jsonify({'prediction': prediction.tolist()})

if __name__ == '__main__':
    app.run(debug=True)