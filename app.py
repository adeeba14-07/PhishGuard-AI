"""
PhishGuard AI - Main Flask Application
This file runs the web server and handles predictions
"""

from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
import ipaddress
from datetime import datetime
import os
import warnings
warnings.filterwarnings('ignore')

# For domain age and typosquatting detection
import whois
from difflib import SequenceMatcher

app = Flask(__name__)

# Load model and feature names
print("🛡️  PhishGuard AI - Starting...")
model_path = 'models/model.pkl'            

if not os.path.exists(model_path):
    print("❌ Model not found! Please run model.py first.")
    print("👉 Run: python model.py")
    exit(1)

model = joblib.load(model_path)
print("✅ Model loaded successfully!")

# Load feature names (if available)
try:
    feature_names = pd.read_csv('models/feature_importance.csv')['feature'].tolist()
except:
    feature_names = [f'feature_{i}' for i in range(30)]
    print("⚠️ Using default feature names")

# List of legitimate domains for typosquatting detection
LEGITIMATE_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'youtube.com', 'netflix.com',
    'paypal.com', 'ebay.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com', 'wikipedia.org'
]

def extract_features(url):
    """
    Extract 30 features from URL for phishing detection
    """
    features = []
    
    try:
        # Parse URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        # 1. URL Length
        features.append(len(url))
        
        # 2. Has HTTPS
        features.append(1 if parsed.scheme == 'https' else 0)
        
        # 3. Number of dots
        features.append(url.count('.'))
        
        # 4. Number of hyphens
        features.append(url.count('-'))
        
        # 5. Number of underscores
        features.append(url.count('_'))
        
        # 6. Number of slashes
        features.append(url.count('/'))
        
        # 7. Number of question marks
        features.append(url.count('?'))
        
        # 8. Number of equals
        features.append(url.count('='))
        
        # 9. Number of @ symbols
        features.append(url.count('@'))
        
        # 10. Number of & symbols
        features.append(url.count('&'))
        
        # 11. Number of ~ symbols
        features.append(url.count('~'))
        
        # 12. Has IP address
        try:
            ipaddress.ip_address(domain)
            features.append(1)
        except:
            features.append(0)
        
        # 13. Domain length
        features.append(len(domain))
        
        # 14. Is shortened URL
        shortening_services = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
        features.append(1 if any(service in domain for service in shortening_services) else 0)
        
        # 15. Number of subdomains
        subdomains = domain.split('.')[:-1] if '.' in domain else []
        features.append(len(subdomains))
        
        # 16. Has port number
        features.append(1 if ':' in domain else 0)
        
        # 17. Has hex code
        features.append(1 if '%' in url else 0)
        
        # 18. Has javascript
        features.append(1 if 'javascript' in url.lower() else 0)
        
        # 19. Has email
        features.append(1 if 'mailto:' in url.lower() or '@' in url else 0)
        
        # 20. Double slash redirect
        features.append(1 if '//' in url[8:] else 0)
        
        # 21. HTTPS in domain
        features.append(1 if 'https' in domain.lower() else 0)
        
        # 22. Percent encoded characters
        features.append(url.count('%'))
        
        # 23. Number of digits
        features.append(sum(c.isdigit() for c in url))
        
        # 24. Number of letters
        features.append(sum(c.isalpha() for c in url))
        
        # 25. TLD length
        tld = domain.split('.')[-1] if '.' in domain else ''
        features.append(len(tld))
        
        # 26. Is HTTPS (duplicate for feature count)
        features.append(1 if parsed.scheme == 'https' else 0)
        
        # 27. Number of parameters
        features.append(url.count('?') + url.count('&'))
        
        # 28. Has anchor
        features.append(1 if '#' in url else 0)
        
        # 29. Has form (checking for 'form' or 'login' in path)
        features.append(1 if 'form' in parsed.path.lower() or 'login' in parsed.path.lower() else 0)
        
        # 30. Has iframe (simplified)
        features.append(1 if 'iframe' in url.lower() else 0)
        
        # Ensure we have exactly 30 features
        while len(features) < 30:
            features.append(0)
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return zeros if extraction fails
        features = [0] * 30
    
    return np.array(features).reshape(1, -1)

def check_domain_age(url):
    """Check domain registration age - newer domains are more suspicious"""
    try:
        domain = urlparse(url).netloc
        if not domain:
            domain = urlparse('http://' + url).netloc
        domain = domain.split(':')[0]
        
        w = whois.whois(domain)
        
        if w.creation_date:
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            age_days = (datetime.now() - creation_date).days
            
            if age_days < 7:
                return {"days": age_days, "risk": "HIGH", "message": f"Domain registered only {age_days} days ago"}
            elif age_days < 30:
                return {"days": age_days, "risk": "MEDIUM", "message": f"Domain registered {age_days} days ago"}
            elif age_days < 365:
                return {"days": age_days, "risk": "LOW", "message": f"Domain registered {age_days} days ago"}
            else:
                return {"days": age_days, "risk": "VERY_LOW", "message": f"Domain registered {age_days // 365} years ago"}
        else:
            return {"days": None, "risk": "UNKNOWN", "message": "Could not determine domain age"}
    except Exception as e:
        return {"days": None, "risk": "UNKNOWN", "message": "WHOIS lookup failed"}

def check_typosquatting(url):
    """Check if URL is a typosquatting attempt (similar to legitimate domains)"""
    domain = urlparse(url).netloc or urlparse('http://' + url).netloc
    domain = domain.replace('www.', '').split(':')[0]
    
    similarities = []
    for legit in LEGITIMATE_DOMAINS:
        ratio = SequenceMatcher(None, domain, legit).ratio()
        if ratio > 0.7 and ratio < 0.95:
            similarities.append({
                'legitimate': legit,
                'similarity': round(ratio * 100, 1),
                'suspicious': ratio > 0.85
            })
    
    if similarities:
        return {
            'is_typosquatting': True,
            'similarities': similarities,
            'message': f"Domain '{domain}' is similar to known legitimate domains"
        }
    else:
        return {
            'is_typosquatting': False,
            'similarities': [],
            'message': 'No typosquatting detected'
        }

def calculate_phishing_score(url):
    """Calculate detailed phishing score breakdown"""
    scores = {}
    total = 0
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    
    # 1. URL Length (max 15 points)
    length = len(url)
    if length > 100:
        scores['URL Length'] = {'points': 15, 'reason': f'Very long URL ({length} chars)'}
        total += 15
    elif length > 75:
        scores['URL Length'] = {'points': 10, 'reason': f'Long URL ({length} chars)'}
        total += 10
    else:
        scores['URL Length'] = {'points': 0, 'reason': 'Normal length'}
    
    # 2. HTTPS Check (max 20 points)
    if parsed.scheme != 'https':
        scores['HTTPS'] = {'points': 20, 'reason': 'No HTTPS encryption'}
        total += 20
    else:
        scores['HTTPS'] = {'points': 0, 'reason': 'Has HTTPS'}
    
    # 3. IP Address (max 25 points)
    try:
        ipaddress.ip_address(domain)
        scores['IP Address'] = {'points': 25, 'reason': 'Uses IP address instead of domain name'}
        total += 25
    except:
        scores['IP Address'] = {'points': 0, 'reason': 'Uses domain name'}
    
    # 4. Special Characters (max 15 points)
    special_chars = url.count('@') + url.count('-') + url.count('_') + url.count('=') + url.count('&')
    if special_chars > 5:
        scores['Special Characters'] = {'points': 15, 'reason': f'Too many special characters ({special_chars})'}
        total += 15
    elif special_chars > 3:
        scores['Special Characters'] = {'points': 10, 'reason': f'Many special characters ({special_chars})'}
        total += 10
    else:
        scores['Special Characters'] = {'points': 0, 'reason': 'Normal special character count'}
    
    # Determine overall risk
    if total >= 60:
        risk = 'HIGH RISK - Phishing'
    elif total >= 35:
        risk = 'MEDIUM RISK - Suspicious'
    else:
        risk = 'LOW RISK - Likely Safe'
    
    return {'total': total, 'max': 100, 'risk': risk, 'breakdown': scores}

@app.route('/')
def home():
    """Render home page"""
    return render_template('index.html', current_year=datetime.now().year)

@app.route('/predict', methods=['POST'])
def predict():
    """Handle prediction requests"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Extract features
        features = extract_features(url)
        
        # Make prediction
        prediction = model.predict(features)[0]
        probabilities = model.predict_proba(features)[0]
        
        # Calculate confidence
        confidence = max(probabilities) * 100
        
        # Determine risk level
        risk_level = 'HIGH' if prediction == 1 else 'LOW'
        
        # Get additional security checks
        domain_info = check_domain_age(url)
        typosquatting = check_typosquatting(url)
        phishing_score = calculate_phishing_score(url)
        
        # Prepare result
        result = {
            'url': url[:50] + '...' if len(url) > 50 else url,
            'full_url': url,
            'is_phishing': bool(prediction),
            'risk_level': risk_level,
            'confidence': round(confidence, 2),
            'features_analyzed': 30,
            'probability_phishing': round(probabilities[1] * 100, 2),
            'probability_safe': round(probabilities[0] * 100, 2),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'domain_age': domain_info,
            'typosquatting': typosquatting,
            'phishing_score': phishing_score
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'timestamp': datetime.now().isoformat()
    })

# ============================================
# NEW ROUTES FOR ADDITIONAL PAGES
# ============================================

@app.route('/dashboard')
def dashboard():
    """Dashboard page with analytics"""
    return render_template('dashboard.html', current_year=datetime.now().year)

@app.route('/reports')
def reports():
    """Reports page for exporting data"""
    return render_template('reports.html', current_year=datetime.now().year)

@app.route('/settings')
def settings():
    """Settings page for user preferences"""
    return render_template('settings.html', current_year=datetime.now().year)

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("🚀 Starting PhishGuard AI Web Application")
    print("=" * 60)
    print("📍 Local URL: http://127.0.0.1:5000")
    print("📍 Network URL: http://localhost:5000")
    print("=" * 60)
    print("📝 Press CTRL+C to stop the server")
    print("=" * 60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)