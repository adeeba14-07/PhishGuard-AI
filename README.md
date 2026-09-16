# 🛡️ PhishGuard AI

An advanced **Machine Learning-based Phishing URL Detector** built with Python, Flask, and Scikit-learn. Analyze URLs instantly to detect phishing attempts before you click.

## 🚀 Features

- **AI-Powered Prediction**: Uses a trained Random Forest model to detect phishing with 30 extracted URL features.
- **Real-time Analysis**: Instant feedback on URL risk (Safe / High Risk).
- **Domain Age Check**: Checks WHOIS data to flag newly registered domains.
- **Typosquatting Detection**: Warns if a URL is suspiciously similar to known legitimate domains (Google, Facebook, etc.).
- **Interactive Dashboard**: View analytics, prediction history (saved locally), and charts using Chart.js.
- **Dark Mode**: Built-in theme toggling.

## 🛠️ Tech Stack

- **Backend**: Flask, Python
- **Machine Learning**: Scikit-learn, Pandas, NumPy
- **Frontend**: HTML5, CSS3, JavaScript, Chart.js

## 📦 Installation & Usage

1. **Clone the repository**
```bash
git clone https://github.com/adeeba14-07/PhishGuard-AI.git
cd PhishGuard-AI
``` 
2.  **Create & Activate Virtual Environment**

```bash
python -m venv venv
Windows: venv\Scripts\activate
Mac/Linux: source venv/bin/activate
```
3. **Install dependencies**

```bash
pip install -r requirements.txt
```
4. **Train the model** (Creates models/model.pkl)

```bash
python model.py
```
5. **Run the application**

```bash
python app.py
```
6. **Open in browser: Go to http://127.0.0.1:5000**

7. **Testing the Application**


    To test the detection, try entering these URLs:

    Safe: https://www.google.com

    Phishing: http://192.168.1.1/login (or a known phishing test URL)

    Check the dashboard to view the risk analysis and confidence score!

## Deployment

This project is deployed on Render :
 Click : https://phishguard-ai-nkte.onrender.com

Build Command: pip install -r requirements.txt

Start Command: gunicorn app:app

Environment Variable: PYTHON_VERSION=3.11.9

Runtime: Python 3

## 📂 Project Structure
```text
PhishGuard-AI/
├── dataset/               # Raw phishing data (.csv)
├── models/                # Saved ML model (.pkl)
├── static/                # CSS and JavaScript files
├── templates/             # HTML templates
├── app.py                 # Main Flask backend
├── model.py               # Model training script
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation
```


## 🤝 Contributing

Contributions are welcome! If you have suggestions for improvements or find bugs:

Fork the repository.

Create a new branch (git checkout -b feature/improvement).

Make your changes.

Commit your changes (git commit -m 'Add some feature').

Push to the branch (git push origin feature/improvement).

Open a Pull Request.  
