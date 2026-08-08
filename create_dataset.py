"""
PhishGuard AI - Dataset Creator
This file creates a realistic phishing dataset for training
"""

import pandas as pd
import numpy as np
import os

print("=" * 60)
print("📊 PhishGuard AI - Dataset Creator")
print("=" * 60)

# Set random seed for reproducibility
np.random.seed(42)

# Number of samples (matching UCI dataset size)
n_samples = 11055

print(f"\n📈 Generating {n_samples} URL samples with 30 features...")

# Generate 30 features for each URL
data = {
    'url_length': np.random.randint(10, 200, n_samples),
    'has_https': np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),
    'num_dots': np.random.randint(1, 10, n_samples),
    'num_hyphens': np.random.randint(0, 5, n_samples),
    'num_underscores': np.random.randint(0, 3, n_samples),
    'num_slashes': np.random.randint(1, 8, n_samples),
    'num_question_marks': np.random.randint(0, 3, n_samples),
    'num_equals': np.random.randint(0, 4, n_samples),
    'num_at_symbols': np.random.randint(0, 2, n_samples),
    'num_ampersands': np.random.randint(0, 3, n_samples),
    'num_tilde': np.random.randint(0, 2, n_samples),
    'has_ip_address': np.random.choice([0, 1], n_samples, p=[0.9, 0.1]),
    'domain_length': np.random.randint(5, 50, n_samples),
    'is_shortened': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
    'num_subdomains': np.random.randint(0, 4, n_samples),
    'has_port': np.random.choice([0, 1], n_samples, p=[0.98, 0.02]),
    'has_hex_code': np.random.choice([0, 1], n_samples, p=[0.97, 0.03]),
    'has_javascript': np.random.choice([0, 1], n_samples, p=[0.85, 0.15]),
    'has_email': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
    'double_slash_redirect': np.random.choice([0, 1], n_samples, p=[0.92, 0.08]),
    'https_in_domain': np.random.choice([0, 1], n_samples, p=[0.88, 0.12]),
    'percent_encoded': np.random.randint(0, 10, n_samples),
    'num_digits': np.random.randint(0, 15, n_samples),
    'num_letters': np.random.randint(5, 50, n_samples),
    'tld_length': np.random.choice([2, 3, 4, 5, 6], n_samples),
    'is_https_duplicate': np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),
    'num_params': np.random.randint(0, 8, n_samples),
    'has_anchor': np.random.choice([0, 1], n_samples, p=[0.8, 0.2]),
    'has_form': np.random.choice([0, 1], n_samples, p=[0.7, 0.3]),
    'has_iframe': np.random.choice([0, 1], n_samples, p=[0.95, 0.05]),
}

df = pd.DataFrame(data)

# Generate labels
# Calculate phishing score based on REALISTIC patterns
phishing_score = (
    # Long URLs (phishing often longer)
    ((df['url_length'] > 75) & (df['url_length'] < 200)) * 0.15 +
    ((df['url_length'] >= 200)) * 0.25 +
    
    # Missing HTTPS (phishing rarely has HTTPS)
    (df['has_https'] == 0) * 0.30 +
    
    # Too many dots (subdomains in phishing)
    (df['num_dots'] >= 4) * 0.15 +
    (df['num_dots'] >= 6) * 0.10 +
    
    # Hyphens (common in phishing)
    (df['num_hyphens'] >= 2) * 0.10 +
    (df['num_hyphens'] >= 4) * 0.10 +
    
    # IP address instead of domain (almost always phishing)
    (df['has_ip_address'] == 1) * 0.35 +
    
    # Shortened URLs (often used in phishing)
    (df['is_shortened'] == 1) * 0.20 +
    
    # Many digits (suspicious)
    (df['num_digits'] >= 8) * 0.10 +
    (df['num_digits'] >= 12) * 0.10 +
    
    # @ symbol (rare in legitimate URLs)
    (df['num_at_symbols'] >= 1) * 0.25 +
    
    # Many parameters (can indicate tracking/fake)
    (df['num_params'] >= 4) * 0.10 +
    
    # JavaScript in URL (suspicious)
    (df['has_javascript'] == 1) * 0.20 +
    
    # Double slash redirect (phishing technique)
    (df['double_slash_redirect'] == 1) * 0.15
)

# Add noise for realism
phishing_score += np.random.randn(n_samples) * 0.08

# Label: 1 if score > 0.4, else 0
df['label'] = (phishing_score > 0.4).astype(int)

phishing_score += np.random.randn(n_samples) * 0.1
df['label'] = (phishing_score > 0.35).astype(int)

# Save to CSV (this fills your empty file!)
df.to_csv('dataset/phishing_dataset.csv', index=False)

print(f"\n✅ Dataset created successfully!")
print(f"📁 Saved to: dataset/phishing_dataset.csv")
print(f"📊 Total samples: {len(df)}")
print(f"🟢 Legitimate: {(df['label'] == 0).sum()} ({(df['label'] == 0).sum()/len(df)*100:.1f}%)")
print(f"🔴 Phishing: {(df['label'] == 1).sum()} ({(df['label'] == 1).sum()/len(df)*100:.1f}%)")