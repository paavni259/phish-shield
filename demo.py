#!/usr/bin/env python3
"""
PhishShield Demo Script
Demonstrates the core functionality of the PhishShield phishing detection system.
"""

from phishshield import PhishShieldDetector
import os

def main():
    print("🛡️ PhishShield - Intelligent Phishing URL Detection System")
    print("=" * 60)
    
    # Check if model exists
    if not os.path.exists('model.pkl'):
        print("❌ Model file not found. Training a new model...")
        detector = PhishShieldDetector()
        
        # Load and train on dataset
        from phishshield import load_uci_dataset
        X, y = load_uci_dataset()
        detector.train_model(X, y)
        detector.save_model('model.pkl')
    else:
        print("✅ Loading pre-trained model...")
        detector = PhishShieldDetector('model.pkl')
    
    print("\n🔍 Testing PhishShield on sample URLs:")
    print("-" * 60)
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://suspicious-site.com/secure-login?verify=account",
        "http://fake-bank.com/update-info",
        "https://www.microsoft.com",
        "https://phishing-example.com/login?redirect=bank.com",
        "https://www.stackoverflow.com",
        "https://malicious-site.net/steal-credentials"
    ]
    
    for i, url in enumerate(test_urls, 1):
        try:
            result = detector.predict(url)
            
            # Color coding for results
            if result['prediction'] == 'Phishing':
                status = "🔴 PHISHING"
            else:
                status = "🟢 LEGITIMATE"
            
            print(f"\n{i}. {url}")
            print(f"   Prediction: {status}")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   Phishing Probability: {result['phishing_probability']:.1%}")
            
        except Exception as e:
            print(f"\n{i}. {url}")
            print(f"   Error: {str(e)}")
    
    print("\n" + "=" * 60)
    print("📊 Model Performance Summary:")
    print("-" * 60)
    
    # Show feature importance
    importance_df = detector.get_feature_importance()
    print("\n🔍 Top 5 Most Important Features:")
    for i, (_, row) in enumerate(importance_df.head(5).iterrows(), 1):
        print(f"{i}. {row['feature']}: {row['importance']:.3f}")
    
    print("\n✨ PhishShield Demo Complete!")
    print("🌐 Run 'streamlit run app.py' for the web interface")
    print("📓 Open 'PhishShield.ipynb' for detailed analysis")

if __name__ == "__main__":
    main()
