#!/usr/bin/env python3
"""
PhishShield Simplified Demo
Shows the streamlined URL detection functionality.
"""

from phishshield_balanced import PhishShieldBalanced
import os

def main():
    print("🛡️ PhishShield Simplified - URL Detection Only")
    print("=" * 60)
    
    # Check if balanced model exists
    if not os.path.exists('balanced_model.pkl'):
        print("❌ Balanced model not found. Training a new model...")
        detector = PhishShieldBalanced()
        
        # Create and train on dataset
        X, y = detector.create_balanced_dataset()
        detector.train_balanced_model(X, y)
        detector.save_balanced_model('balanced_model.pkl')
    else:
        print("✅ Loading pre-trained balanced model...")
        detector = PhishShieldBalanced('balanced_model.pkl')
    
    print("\n🔍 PhishShield URL Detection Demo")
    print("-" * 60)
    print("Enter URLs to analyze (type 'quit' to exit):")
    
    while True:
        url = input("\n🌐 Enter URL: ").strip()
        
        if url.lower() in ['quit', 'exit', 'q']:
            print("👋 Goodbye!")
            break
        
        if not url:
            print("⚠️ Please enter a valid URL.")
            continue
        
        try:
            result = detector.predict_balanced(url)
            
            # Color coding
            if result['prediction'] == 'Phishing':
                status = "🔴 PHISHING"
            else:
                status = "🟢 LEGITIMATE"
            
            print(f"\n📊 Analysis Results:")
            print(f"   URL: {result['url']}")
            print(f"   Prediction: {status}")
            print(f"   Risk Level: {result['risk_level']}")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   Phishing Probability: {result['phishing_probability']:.1%}")
            
        except Exception as e:
            print(f"❌ Error analyzing URL: {str(e)}")

if __name__ == "__main__":
    main()
