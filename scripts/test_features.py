import sys
sys.path.insert(0, '.')
from backend.ml.feature_engineering import extract_url_features

phishing = 'http://paypa1-secure-login.tk/verify?user=victim'
safe     = 'https://www.google.com/search?q=weather'

f1 = extract_url_features(phishing)
f2 = extract_url_features(safe)

print("--- PHISHING URL ---")
print("  URLSimilarityIndex :", round(f1["URLSimilarityIndex"], 4), " (LOW = phishing)")
print("  TLDLegitimateProb  :", round(f1["TLDLegitimateProb"], 4), " (.tk = 0.1)")
print("  IsHTTPS            :", f1["IsHTTPS"], " (http = 0)")
print("  HasPasswordField   :", f1["HasPasswordField"])
print("  NoOfSubDomain      :", f1["NoOfSubDomain"])
print("  Total features     :", len(f1))
print()
print("--- SAFE URL ---")
print("  URLSimilarityIndex :", round(f2["URLSimilarityIndex"], 4), " (HIGH = legitimate)")
print("  TLDLegitimateProb  :", round(f2["TLDLegitimateProb"], 4), " (.com = 1.0)")
print("  IsHTTPS            :", f2["IsHTTPS"], " (https = 1)")
print("  Total features     :", len(f2))
