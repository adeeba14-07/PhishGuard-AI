// PhishGuard AI - Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Get DOM elements
    const urlInput = document.getElementById('urlInput');
    const checkBtn = document.getElementById('checkBtn');
    const loader = document.getElementById('loader');
    const resultsSection = document.getElementById('resultsSection');
    const statusIndicator = document.getElementById('statusIndicator');
    const suspiciousFeatures = document.getElementById('suspiciousFeatures');
    
    // Set initial status
    if (statusIndicator) statusIndicator.style.background = '#10b981';
    
    // Add event listeners
    if (checkBtn) checkBtn.addEventListener('click', checkURL);
    if (urlInput) {
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') checkURL();
        });
    }
    
    // Function to check URL
    async function checkURL() {
        const url = urlInput.value.trim();
        
        if (!url) {
            alert('Please enter a URL');
            return;
        }
        
        if (loader) loader.style.display = 'block';
        if (resultsSection) resultsSection.style.display = 'none';
        if (suspiciousFeatures) suspiciousFeatures.style.display = 'none';
        if (statusIndicator) statusIndicator.style.background = '#f59e0b';
        
        // Add loading effect to button
        if (checkBtn) {
            checkBtn.classList.add('loading');
            checkBtn.disabled = true;
        }
        
        try {
            const response = await fetch('/predict', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            
            const data = await response.json();
            if (data.error) throw new Error(data.error);
            
            displayResults(data);
            saveToHistory(data);
            
        } catch (error) {
            if (loader) loader.style.display = 'none';
            alert('Error analyzing URL: ' + error.message);
            if (statusIndicator) statusIndicator.style.background = '#ef4444';
        } finally {
            if (checkBtn) {
                checkBtn.classList.remove('loading');
                checkBtn.disabled = false;
            }
        }
    }
    
    // Function to display results
    function displayResults(data) {
        document.getElementById('analyzedUrl').textContent = data.url;
        
        const riskLevel = document.getElementById('riskLevel');
        riskLevel.textContent = data.risk_level;
        riskLevel.className = data.is_phishing ? 'risk-high' : 'risk-low';
        
        document.getElementById('confidenceValue').textContent = data.confidence + '%';
        document.getElementById('featuresCount').textContent = data.features_analyzed;
        
        const safetyScore = data.is_phishing ? 100 - data.confidence : data.confidence;
        document.getElementById('safetyScore').textContent = Math.round(safetyScore) + '%';
        document.getElementById('meterFill').style.width = safetyScore + '%';
        
        document.getElementById('safeBar').style.width = data.probability_safe + '%';
        document.getElementById('phishingBar').style.width = data.probability_phishing + '%';
        document.getElementById('safeProb').textContent = data.probability_safe + '%';
        document.getElementById('phishingProb').textContent = data.probability_phishing + '%';
        
        document.getElementById('timestamp').textContent = data.timestamp;
        
        const recommendation = document.getElementById('recommendation');
        if (data.is_phishing) {
            recommendation.innerHTML = '⚠️ <strong>WARNING:</strong> This appears to be a phishing website! Do not enter any personal information.';
            recommendation.className = 'recommendation unsafe';
            if (statusIndicator) statusIndicator.style.background = '#ef4444';
            if (suspiciousFeatures) suspiciousFeatures.style.display = 'block';
        } else {
            recommendation.innerHTML = '✅ <strong>SAFE:</strong> This website appears to be legitimate.';
            recommendation.className = 'recommendation safe';
            if (statusIndicator) statusIndicator.style.background = '#10b981';
            if (suspiciousFeatures) suspiciousFeatures.style.display = 'none';
        }
        
        // Display domain age info
        if (data.domain_age && data.domain_age.message) {
            const domainDiv = document.getElementById('domainAgeInfo');
            domainDiv.innerHTML = `<strong>📅 Domain Age:</strong> ${data.domain_age.message}`;
            domainDiv.style.display = 'block';
        }
        
        // Display typosquatting alert
        if (data.typosquatting && data.typosquatting.is_typosquatting) {
            const alertDiv = document.getElementById('typosquattingAlert');
            const contentDiv = document.getElementById('typosquattingContent');
            let html = `<p>${data.typosquatting.message}</p><ul>`;
            data.typosquatting.similarities.forEach(sim => {
                html += `<li>Similar to <strong>${sim.legitimate}</strong> (${sim.similarity}% similar)</li>`;
            });
            html += '</ul>';
            contentDiv.innerHTML = html;
            alertDiv.style.display = 'block';
        } else {
            document.getElementById('typosquattingAlert').style.display = 'none';
        }
        
        // Display phishing score breakdown
        if (data.phishing_score) {
            const breakdownDiv = document.getElementById('scoreBreakdown');
            const breakdownContent = document.getElementById('breakdownContent');
            let html = `<p><strong>Total Score:</strong> ${data.phishing_score.total}/100</p>
                        <p><strong>Risk Level:</strong> ${data.phishing_score.risk}</p>
                        <ul>`;
            for (const [key, value] of Object.entries(data.phishing_score.breakdown)) {
                html += `<li><strong>${key}:</strong> ${value.points} points - ${value.reason}</li>`;
            }
            html += '</ul>';
            breakdownContent.innerHTML = html;
            breakdownDiv.style.display = 'block';
        }
        
        if (loader) loader.style.display = 'none';
        if (resultsSection) resultsSection.style.display = 'block';
    }
    
    window.setTestUrl = function(url) {
        if (urlInput) urlInput.value = url;
        checkURL();
    };
});

// ============================================
// ENHANCEMENT FUNCTIONS
// ============================================

// Copy to Clipboard
function copyResultToClipboard() {
    const url = document.getElementById('analyzedUrl')?.innerText || 'N/A';
    const riskLevel = document.getElementById('riskLevel')?.innerText || 'N/A';
    const confidence = document.getElementById('confidenceValue')?.innerText || 'N/A';
    const recommendation = document.getElementById('recommendation')?.innerText || 'N/A';
    const timestamp = document.getElementById('timestamp')?.innerText || new Date().toLocaleString();
    
    const copyContent = `========================================
PHISHGUARD AI - PREDICTION REPORT
========================================
Time: ${timestamp}
URL: ${url}
Risk Level: ${riskLevel}
Confidence: ${confidence}
Verdict: ${recommendation}
========================================`;
    
    navigator.clipboard.writeText(copyContent);
    alert('✅ Result copied to clipboard!');
}

// Export as TXT
function exportResults() {
    const url = document.getElementById('analyzedUrl')?.innerText || 'N/A';
    const riskLevel = document.getElementById('riskLevel')?.innerText || 'N/A';
    const confidence = document.getElementById('confidenceValue')?.innerText || 'N/A';
    const recommendation = document.getElementById('recommendation')?.innerText || 'N/A';
    const timestamp = document.getElementById('timestamp')?.innerText || new Date().toLocaleString();
    
    const content = `========================================
PHISHGUARD AI - PREDICTION REPORT
========================================
Report Generated: ${timestamp}
========================================

URL ANALYZED: ${url}
RISK LEVEL: ${riskLevel}
CONFIDENCE: ${confidence}

VERDICT:
${recommendation}

========================================
Features Analyzed: 30
Model: Random Forest Classifier
Accuracy: 81%
========================================`;
    
    const blob = new Blob([content], { type: 'text/plain' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `phishguard_report_${Date.now()}.txt`;
    link.click();
    URL.revokeObjectURL(link.href);
}

// Prediction History
let predictionHistory = JSON.parse(localStorage.getItem('phishguard_history') || '[]');

function saveToHistory(data) {
    const historyItem = {
        url: data.url,
        fullUrl: data.full_url || data.url,
        result: data.is_phishing ? 'PHISHING' : 'SAFE',
        confidence: data.confidence,
        riskLevel: data.risk_level,
        timestamp: new Date().toLocaleString()
    };
    predictionHistory.unshift(historyItem);
    if (predictionHistory.length > 20) predictionHistory.pop();
    localStorage.setItem('phishguard_history', JSON.stringify(predictionHistory));
}

function displayHistory() {
    const historyContainer = document.getElementById('historyContainer');
    if (!historyContainer) return;
    
    if (predictionHistory.length === 0) {
        historyContainer.innerHTML = '<div class="history-empty">No predictions yet. Check some URLs!</div>';
        return;
    }
    
    let html = '<div class="history-list">';
    predictionHistory.forEach((item) => {
        const resultClass = item.result === 'SAFE' ? 'history-safe' : 'history-phishing';
        const resultIcon = item.result === 'SAFE' ? '✅' : '⚠️';
        html += `
            <div class="history-item ${resultClass}">
                <div class="history-url" title="${item.fullUrl}">
                    ${item.url.length > 50 ? item.url.substring(0, 50) + '...' : item.url}
                </div>
                <div class="history-details">
                    <span class="history-result">${resultIcon} ${item.result}</span>
                    <span class="history-confidence">${item.confidence}%</span>
                    <span class="history-time">${item.timestamp}</span>
                </div>
            </div>
        `;
    });
    html += '</div>';
    historyContainer.innerHTML = html;
}

function showHistory() {
    const historySection = document.getElementById('historySection');
    if (!historySection) return;
    
    if (historySection.style.display === 'none') {
        historySection.style.display = 'block';
        displayHistory();
    } else {
        historySection.style.display = 'none';
    }
}

function toggleHistory() {
    const historySection = document.getElementById('historySection');
    if (historySection.style.display === 'none') {
        historySection.style.display = 'block';
        displayHistory();
    } else {
        historySection.style.display = 'none';
    }
}

// Batch URL Check
let scannedUrl = '';

function toggleBatchMode() {
    const batchMode = document.getElementById('batchMode');
    if (batchMode.style.display === 'none') {
        batchMode.style.display = 'block';
    } else {
        batchMode.style.display = 'none';
    }
}

async function batchCheckURLs() {
    const fileInput = document.getElementById('batchFile');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Please select a CSV file');
        return;
    }
    
    const resultsDiv = document.getElementById('batchResults');
    resultsDiv.innerHTML = '<p>⏳ Processing URLs... Please wait...</p>';
    
    const reader = new FileReader();
    reader.onload = async function(e) {
        const content = e.target.result;
        const lines = content.split('\n').filter(line => line.trim() && line.startsWith('http'));
        const results = [];
        
        for (let i = 0; i < lines.length; i++) {
            const url = lines[i].trim();
            try {
                resultsDiv.innerHTML = `<p>⏳ Checking ${i+1}/${lines.length}: ${url.substring(0, 50)}...</p>`;
                const response = await fetch('/predict', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();
                results.push({
                    url: url.substring(0, 50),
                    result: data.is_phishing ? '⚠️ PHISHING' : '✅ SAFE',
                    confidence: data.confidence
                });
            } catch (error) {
                results.push({ url: url.substring(0, 50), result: '❌ ERROR', confidence: 0 });
            }
        }
        
        let html = '<table style="width: 100%; border-collapse: collapse; margin-top: 1rem;">';
        html += '<tr style="background: #6366f1; color: white;"><th style="padding: 10px;">URL</th><th>Result</th><th>Confidence</th></tr>';
        results.forEach(r => {
            const rowColor = r.result.includes('SAFE') ? '#d1fae5' : (r.result.includes('PHISHING') ? '#fee2e2' : '#fff3cd');
            html += `<tr style="background: ${rowColor}; border-bottom: 1px solid #ddd;">
                        <td style="padding: 8px;">${r.url}</td>
                        <td style="padding: 8px;">${r.result}</td>
                        <td style="padding: 8px;">${r.confidence}%</td>
                    </tr>`;
        });
        html += '</table>';
        resultsDiv.innerHTML = html;
        alert(`✅ Batch check complete! Checked ${results.length} URLs`);
    };
    reader.readAsText(file);
}

function displayBatchResults(results) {
    const container = document.getElementById('batchResults');
    let html = '<table style="width: 100%; border-collapse: collapse;">';
    html += '<tr style="background: #6366f1; color: white;"><th style="padding: 10px;">URL</th><th>Result</th><th>Confidence</th></tr>';
    results.forEach(r => {
        const rowColor = r.result.includes('SAFE') ? '#d1fae5' : (r.result.includes('PHISHING') ? '#fee2e2' : '#fff3cd');
        html += `<tr style="background: ${rowColor}; border-bottom: 1px solid #ddd;">
                    <td style="padding: 8px;">${r.url}</td>
                    <td style="padding: 8px;">${r.result}</td>
                    <td style="padding: 8px;">${r.confidence}%</td>
                 </tr>`;
    });
    html += '</table>';
    container.innerHTML = html;
}

// QR Code Scanner
function toggleQRMode() {
    const qrMode = document.getElementById('qrMode');
    if (qrMode.style.display === 'none') {
        qrMode.style.display = 'block';
        if (typeof Html5Qrcode !== 'undefined') {
            const html5QrCode = new Html5Qrcode("qr-reader");
            html5QrCode.start(
                { facingMode: "environment" },
                { fps: 10, qrbox: { width: 250, height: 250 } },
                (decodedText) => {
                    scannedUrl = decodedText;
                    document.getElementById('qr-result').innerHTML = `✅ Scanned: ${scannedUrl.substring(0, 50)}...`;
                    html5QrCode.stop();
                },
                (error) => { console.log(error); }
            );
        }
    } else {
        qrMode.style.display = 'none';
    }
}

function checkQRUrl() {
    if (scannedUrl) {
        document.getElementById('urlInput').value = scannedUrl;
        document.getElementById('checkBtn').click();
        toggleQRMode();
    } else {
        alert('Please scan a QR code first');
    }
}

// Theme Toggle
function toggleTheme() {
    document.body.classList.toggle('dark-mode');
    const isDark = document.body.classList.contains('dark-mode');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
    
    const themeBtn = document.querySelector('.theme-toggle');
    if (themeBtn) themeBtn.textContent = isDark ? '☀️' : '🌙';
}

const savedTheme = localStorage.getItem('theme');
if (savedTheme === 'dark') {
    document.body.classList.add('dark-mode');
    const themeBtn = document.querySelector('.theme-toggle');
    if (themeBtn) themeBtn.textContent = '☀️';
}

// Navigation Functions
function showSection(section) {
    const homeLink = document.getElementById('homeLink');
    const howLink = document.getElementById('howLink');
    const aboutLink = document.getElementById('aboutLink');
    const hero = document.querySelector('.hero');
    const detectorCard = document.querySelector('.detector-card');
    const featuresSection = document.getElementById('how-it-works');
    const testSection = document.querySelector('.test-section');
    const aboutPageContent = document.getElementById('aboutPageContent');
    const historySection = document.getElementById('historySection');
    
    if (homeLink) homeLink.classList.remove('active');
    if (howLink) howLink.classList.remove('active');
    if (aboutLink) aboutLink.classList.remove('active');
    
    if (section === 'home') {
        if (homeLink) homeLink.classList.add('active');
        if (hero) hero.style.display = 'block';
        if (detectorCard) detectorCard.style.display = 'block';
        if (featuresSection) featuresSection.style.display = 'block';
        if (testSection) testSection.style.display = 'block';
        if (aboutPageContent) aboutPageContent.style.display = 'none';
        if (historySection) historySection.style.display = 'none';
    } 
    else if (section === 'how-it-works') {
        if (howLink) howLink.classList.add('active');
        if (hero) hero.style.display = 'block';
        if (detectorCard) detectorCard.style.display = 'block';
        if (featuresSection) featuresSection.style.display = 'block';
        if (testSection) testSection.style.display = 'block';
        if (aboutPageContent) aboutPageContent.style.display = 'none';
        if (historySection) historySection.style.display = 'none';
        setTimeout(() => {
            if (featuresSection) featuresSection.scrollIntoView({ behavior: 'smooth' });
        }, 100);
    } 
    else if (section === 'about') {
        if (aboutLink) aboutLink.classList.add('active');
        if (hero) hero.style.display = 'none';
        if (detectorCard) detectorCard.style.display = 'none';
        if (featuresSection) featuresSection.style.display = 'none';
        if (testSection) testSection.style.display = 'none';
        if (aboutPageContent) aboutPageContent.style.display = 'block';
        if (historySection) historySection.style.display = 'none';
    }
}

function showHomePage() {
    showSection('home');
}

window.onload = function() {
    showSection('home');
};


function toggleQRScanner() {
    const scanner = document.getElementById('qrScanner');
    if (scanner) {
        scanner.style.display = scanner.style.display === 'none' ? 'block' : 'none';
    }
}

function scanQRCode() {
    const fileInput = document.getElementById('qrImage');
    const file = fileInput ? fileInput.files[0] : null;
    
    if (!file) {
        alert('Please select a QR code image');
        return;
    }
    
    alert('Please look at the QR code and type the URL manually.\n\nEnter the URL from the QR code below:');
    
    const manualUrl = prompt('Enter the URL from the QR code:');
    if (manualUrl && manualUrl.startsWith('http')) {
        document.getElementById('urlInput').value = manualUrl;
        document.getElementById('checkBtn').click();
    } else if (manualUrl) {
        alert('Please enter a valid URL starting with http:// or https://');
    }
}
// ============================================
// QR CODE SCANNER - WORKING VERSION
// ============================================

let qrScannerActive = false;

function toggleQRScanner() {
    const scanner = document.getElementById('qrScanner');
    if (scanner) {
        qrScannerActive = !qrScannerActive;
        scanner.style.display = qrScannerActive ? 'block' : 'none';
        if (!qrScannerActive) {
            document.getElementById('qrScanResult').innerHTML = '';
        }
    }
}

function scanQRCodeImage() {
    const fileInput = document.getElementById('qrImageInput');
    const file = fileInput.files[0];
    const resultDiv = document.getElementById('qrScanResult');
    
    if (!file) {
        alert('Please select a QR code image first');
        return;
    }
    
    resultDiv.innerHTML = '<span style="color: #6366f1;">⏳ Scanning image...</span>';
    
    const reader = new FileReader();
    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = img.width;
            canvas.height = img.height;
            ctx.drawImage(img, 0, 0, img.width, img.height);
            
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            
            if (typeof jsQR !== 'undefined') {
                const code = jsQR(imageData.data, canvas.width, canvas.height);
                if (code) {
                    const qrUrl = code.data;
                    resultDiv.innerHTML = `<span style="color: #10b981;">✅ QR Code detected!</span><br>URL: ${qrUrl.substring(0, 80)}${qrUrl.length > 80 ? '...' : ''}<br><br>
                        <button onclick="useQRUrl('${qrUrl.replace(/'/g, "\\'")}')" class="check-btn" style="padding: 0.5rem 1rem;">🔍 Check This URL</button>`;
                } else {
                    resultDiv.innerHTML = '<span style="color: #ef4444;">❌ No QR code found in this image. Please try another image.</span>';
                }
            } else {
                resultDiv.innerHTML = '<span style="color: #ef4444;">⚠️ QR library loading failed. Please refresh the page.</span>';
            }
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function useQRUrl(url) {
    document.getElementById('urlInput').value = url;
    document.getElementById('checkBtn').click();
    toggleQRScanner();
}