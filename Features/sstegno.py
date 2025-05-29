from flask import Flask, request, jsonify
import cv2
import numpy as np
from scipy.stats import chisquare
import scipy.fftpack as fftpack
from skimage.measure import shannon_entropy
import os
import uuid
from werkzeug.utils import secure_filename
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def analyze_video(video_path):
    """
    Analyze video for steganography and return results.
    """
    cap = cv2.VideoCapture(video_path)
    frame_count = 0
    results = {
        'suspicious_frames': [],
        'dct_anomalies': [],
        'entropy_anomalies': [],
        'lsb_distribution': [],
        'frame_count': 0,
        'chi_square': {'statistic': None, 'p_value': None, 'conclusion': None}
    }

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        frame_count += 1
        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        lsb_frame = np.bitwise_and(gray_frame, 1)

        # Store LSB frequency for statistical analysis
        unique, counts = np.unique(lsb_frame, return_counts=True)
        results['lsb_distribution'].append(counts.tolist())

        if np.any(lsb_frame):
            results['suspicious_frames'].append(frame_count)

        # DCT analysis
        dct_transform = fftpack.dct(fftpack.dct(np.float32(gray_frame), axis=0, norm='ortho'), axis=1, norm='ortho')
        dct_mean = np.mean(dct_transform)
        if dct_mean > 50:
            results['dct_anomalies'].append(frame_count)

        # Entropy analysis
        entropy_value = shannon_entropy(gray_frame)
        if entropy_value > 7.5:
            results['entropy_anomalies'].append(frame_count)

    cap.release()
    results['frame_count'] = frame_count

    # Chi-square test
    if results['lsb_distribution']:
        observed = np.sum(results['lsb_distribution'], axis=0)
        expected = np.full_like(observed, np.mean(observed))
        chi_stat, p_value = chisquare(observed, expected)

        results['chi_square']['statistic'] = chi_stat
        results['chi_square']['p_value'] = p_value
        results['chi_square'][
            'conclusion'] = "High likelihood of steganography" if p_value < 0.05 else "No significant anomalies"

    return results


@app.route('/vid_stegnography', methods=['POST'])
def detect_steganography():
    """
    API endpoint for detecting steganography in videos.
    """
    # Check if file was uploaded
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    # Check if file has allowed extension
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    # Save the file temporarily
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        # Analyze the video
        results = analyze_video(filepath)

        # Clean up - remove the temporary file
        os.remove(filepath)

        return jsonify({
            'status': 'success',
            'results': results
        })
    except Exception as e:
        # Clean up if error occurs
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)