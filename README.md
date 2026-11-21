# URL-Based Phishing Detection Using Machine Learning

A comprehensive machine learning project for detecting phishing websites through URL analysis. This project combines a trained ML model with a user-friendly web interface to help users identify potentially malicious URLs.

## 🚀 Features

- **Machine Learning Model**: Trained on a dataset of 11,055 URLs using 21 distinct features
- **Web Interface**: Clean, responsive Flask-based web application
- **URL Analyzer**: Automated feature extraction from URLs
- **Real-time Detection**: Instant analysis and prediction results
- **Comprehensive Testing**: Multiple test scripts for validation
- **Educational Resources**: Detailed testing guide and feature explanations

## 🛠️ Technologies Used

- **Backend**: Python, Flask
- **Machine Learning**: Scikit-learn, Pandas, NumPy
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Visualization**: Matplotlib, Seaborn
- **Data Processing**: Pandas, NumPy

## 📊 Dataset

The model is trained on a phishing website dataset containing:
- 11,055 URLs (5,528 phishing, 5,527 legitimate)
- 21 features extracted from URL characteristics
- Binary classification: Safe (-1), Suspicious (0), Not Safe (1)

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/url-phishing-detection.git
   cd url-phishing-detection
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Ensure model file is present**:
   - The `Phishing_model.pkl` file should be in the root directory
   - If missing, run the training scripts to generate it

## 🚀 Usage

1. **Start the web application**:
   ```bash
   python backend/app.py
   ```

2. **Open your browser** and navigate to `http://localhost:5000`

3. **Analyze URLs**:
   - Use the web interface to input URLs or features
   - The model will predict if the URL is safe, suspicious, or phishing

## 📁 Project Structure

```
├── app.py                    # Main Flask application
├── url_analyzer.py          # URL feature extraction module
├── Phishing_model.pkl       # Trained ML model (generated)
├── phishing.csv            # Training dataset
├── requirements.txt         # Python dependencies
├── templates/              # HTML templates
│   ├── index.html
│   ├── Inspect.html
│   └── output.html
├── static/                 # CSS, JS, images
├── URL_TESTING_GUIDE.md    # Testing guide and examples
├── *.ipynb                 # Jupyter notebooks for analysis
└── test_*.py              # Various testing scripts
```

## 🧪 Testing

Run the included test scripts to validate the model:

```bash
python backend/test_phishing.py
python backend/test_url_analyzer.py
python backend/test_all_predictions.py

# Complete automated suite
cd backend
python -m unittest discover -s tests -v
```

## 📈 Model Performance

The trained model achieves high accuracy in detecting phishing URLs through analysis of:
- Domain characteristics (IP usage, subdomains, HTTPS)
- URL structure (prefix/suffix, abnormal patterns)
- Content features (anchor links, scripts, forms)
- Domain reputation (age, DNS, traffic)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 📞 Contact

For questions or suggestions, please open an issue on GitHub.

---

