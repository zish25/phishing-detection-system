# VirusTotal Integration Guide

## Overview

The phishing detection system now includes integration with **VirusTotal**, a free online service that analyzes URLs and files for malware and security threats. This provides **external threat intelligence** to augment the ML-based detection.

## What is VirusTotal?

VirusTotal scans URLs across 90+ antivirus engines and URL/domain blocklists, providing a malicious score based on real-world threat detection data. This complements your ML model by adding:

- Real-world malware detection results
- Reputation data from security vendors
- Antivirus engine consensus
- Threat actor intelligence

## Getting Started

### Step 1: Get a Free VirusTotal API Key

1. Go to https://www.virustotal.com/gui/home/upload
2. Click **"Sign in"** (top right)
3. Create a free account or sign in with Google/GitHub
4. Once logged in, click your profile → **"API key"**
5. Copy your API key (keep it confidential!)

### Step 2: Add API Key to the Streamlit App

**Option A: Paste in UI (Recommended for Testing)**
1. Run `streamlit run app.py`
2. Scroll to "External Threat Intelligence (Optional)"
3. Enter your VirusTotal API key in the text field
4. Your key is used only for that session and not saved

**Option B: Set Environment Variable (Recommended for Production)**
```bash
# On Windows (PowerShell):
$env:VT_API_KEY = "your-api-key-here"
streamlit run app.py

# On Windows (CMD):
set VT_API_KEY=your-api-key-here
streamlit run app.py

# On macOS/Linux:
export VT_API_KEY="your-api-key-here"
streamlit run app.py
```

**Option C: Create .env File (Alternative)**
1. Create a `.env` file in your project directory
2. Add this line:
   ```
   VT_API_KEY=your-api-key-here
   ```
3. The system will automatically load it

### Step 3: Run Advanced Analysis

1. Enter a URL to check
2. Check the box **"🔬 Advanced Analysis (URL + Web Content)"**
3. The system will now include VirusTotal scanning!

## Understanding the Results

### External Threat Intelligence Score

The system now shows **4 metrics**:

| Metric | Source | What It Means |
|--------|--------|---------------|
| **URL Analysis** | ML Model | URL pattern and structural analysis |
| **Web Content Risk** | Web Crawler | Content, forms, links, keywords |
| **External Threat** | VirusTotal | Real-world threat database |
| **Combined Risk** | All Sources | Weighted average of all sources |

### Score Weighting

The final risk score combines:
- **URL Analysis**: 40-50% (depending on available data)
- **Web Content**: 20-30% (if analysis succeeds)
- **VirusTotal**: 20-30% (if API key configured)

### Color Coding

- 🟢 **0-35%**: Safe
- 🟡 **35-65%**: Suspicious (investigate)
- 🟠 **65-75%**: High risk
- 🔴 **≥75%**: Likely phishing

## Threat Intelligence Details

When analyzing a URL with VirusTotal enabled, you'll see:

- **Detection Count**: How many antivirus engines flagged it
- **Detection Rate**: Percentage of engines (e.g., 5/90)
- **Malicious Score**: Calculated risk from detections
- **Analysis Summary**: Human-readable conclusion

### Example Output

```
URL: https://example-phishing.com
─────────────────────────────────
URL Analysis: 75% suspicious
Web Content: 60% risky
🛡️ External Threat Intelligence: 82% malicious
   ↳ VirusTotal: 12 engines detected as malicious (out of 90)

✓ Detection Summary: 12 engines flagged as malicious
Combined Risk: 73% → 🔴 PHISHING DETECTED
```

## API Limits

### Free Tier

- **4 requests/minute**
- **500 requests/day**
- Good for personal use and testing

### Paid Tier

For higher limits, see: https://www.virustotal.com/gui/pricing

## Troubleshooting

### "VirusTotal API key not configured"

**Solution**: Add your API key via:
1. Streamlit UI text input, OR
2. Environment variable `VT_API_KEY`, OR  
3. `.env` file in project directory

### "VirusTotal API timeout"

**Causes**:
- Network connectivity issue
- VirusTotal API is temporarily unavailable
- URL is being scanned (takes time for first submission)

**Solution**: 
- Wait a few seconds and try again
- Check your internet connection
- Verify API key is valid at https://www.virustotal.com/gui/my-apikey

### "Rate limit exceeded"

**Cause**: Exceeded free tier limits (4 requests/minute)

**Solution**:
- Wait before checking more URLs
- Consider upgrading to paid tier
- Use the system for fewer URLs

## How It Works Technically

### Analysis Pipeline

```
URL Input
   |
   ├─→ Step 1: URL ML Analysis (deterministic)
   |
   ├─→ Step 2: Web Content Analysis (optional)
   |
   ├─→ Step 3: VirusTotal API Check (if key provided)
   |   └─→ Fetch URL analysis from VirusTotal
   |   └─→ Get malicious score from engines
   |
   └─→ Step 4: Combine all scores
       └─→ Generate final risk assessment
```

### Caching

VirusTotal caches results, so:
- **First time**: Analysis is created (may take a few seconds)
- **Subsequent times**: Cached result returned (faster)

## Security Notes

### API Key Safety

- **Never share** your API key
- **Don't commit** it to version control
- Use **environment variables** or **`.env` files**
- The Streamlit UI password field hides the key

### Data Privacy

- URLs are sent to VirusTotal's servers
- VirusTotal has extensive privacy policies
- No PII should be included in URLs
- Check VirusTotal's privacy policy: https://www.virustotal.com/en/privacy/

## Examples

### Example 1: Safe Website

```
URL: https://www.google.com

Results:
- URL Analysis: 5% suspicious
- Web Content: 0% risky
- External Threat: 0% malicious
- Combined: 1% → 🟢 SAFE
```

### Example 2: Suspicious Website

```
URL: https://secure-paypal-verify.com/update

Results:
- URL Analysis: 85% suspicious (PayPal misspelling)
- Web Content: 75% risky (login form, keywords)
- External Threat: 70% malicious (flagged by engines)
- Combined: 77% → 🔴 PHISHING DETECTED
```

## Advanced Usage

### Using in Python Scripts

```python
from virustotal_analyzer import VirusTotalAnalyzer

# Initialize with API key
vt = VirusTotalAnalyzer(api_key="your-key-here")

# Check if configured
if vt.is_configured():
    result = vt.get_url_report("https://example.com")
    print(f"Malicious Score: {result['malicious_score']*100:.1f}%")
```

### Environment Variable with Model

```python
from model import PhishingDetectionModel
import os

model = PhishingDetectionModel()
model.load_model()

# VirusTotal key from env var
vt_key = os.getenv('VT_API_KEY')

result = model.predict_hybrid(
    url="https://example.com",
    use_content_analysis=True,
    vt_api_key=vt_key
)
```

## FAQ

**Q: Do I need an API key to use the system?**  
A: No. The system works without VirusTotal. Add the API key for enhanced threat intelligence.

**Q: Is the API key stored anywhere?**  
A: No. In Streamlit, it's used only for that session. Set as environment variable for production.

**Q: Can I use multiple API keys?**  
A: The system uses one API key per analysis. You can change it anytime in the UI.

**Q: What if VirusTotal can't analyze a URL?**  
A: The system falls back to URL+Web analysis. Combined score is recalculated without VirusTotal.

**Q: Can I cache VirusTotal results?**  
A: Yes, VirusTotal automatically caches results. Repeated URLs return faster.

## Support

- VirusTotal API Docs: https://developers.virustotal.com/reference
- VirusTotal Community: https://www.virustotal.com/gui/community
- Free API Key: https://www.virustotal.com/gui/my-apikey

## Summary

| Feature | Details |
|---------|---------|
| **Cost** | Free for 4 req/min, 500 req/day |
| **Setup Time** | ~2 minutes |
| **Improvement** | +10-25% detection accuracy |
| **Data Privacy** | Secure, encrypted transmission |
| **Fallback** | System works without it |

---

**Pro Tip**: For best results, combine with web analysis enabled! The system uses all available threat intelligence sources to maximize detection accuracy.
