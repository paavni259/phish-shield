"""
PhishShield Web Interface
Streamlit-based web application for phishing URL detection.
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from phishshield import PhishShieldDetector
from enhanced_phishshield import EnhancedPhishShieldDetector
from phishshield_balanced import PhishShieldBalanced
import os

# Page configuration
st.set_page_config(
    page_title="PhishShield - Phishing URL Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .prediction-box {
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .phishing {
        background-color: #ffebee;
        border-left: 5px solid #f44336;
    }
    .legitimate {
        background-color: #e8f5e8;
        border-left: 5px solid #4caf50;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

def load_model():
    """Load the trained model."""
    try:
        if os.path.exists('balanced_model.pkl'):
            detector = PhishShieldBalanced('balanced_model.pkl')
            return detector, "Balanced"
        elif os.path.exists('enhanced_model.pkl'):
            detector = EnhancedPhishShieldDetector('enhanced_model.pkl')
            return detector, "Enhanced"
        elif os.path.exists('model.pkl'):
            detector = PhishShieldDetector('model.pkl')
            return detector, "Original"
        else:
            st.error("Model file not found. Please train the model first.")
            return None, None
    except Exception as e:
        st.error(f"Error loading model: {str(e)}")
        return None, None

def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ PhishShield</h1>', unsafe_allow_html=True)
    st.markdown('<h2 style="text-align: center; color: #666;">Intelligent Phishing URL Detection System</h2>', unsafe_allow_html=True)
    
    # Sidebar information
    st.sidebar.title("🛡️ PhishShield")
    st.sidebar.markdown("**Intelligent Phishing URL Detection**")
    
    st.sidebar.markdown("""
    ### 🎯 Features
    - Real-time URL analysis
    - 90.4% accuracy
    - Risk level assessment
    - Confidence scoring
    
    ### 🔍 How it works
    1. Enter any URL
    2. Click "Analyze"
    3. Get instant results
    4. View risk level
    
    ### ⚠️ Disclaimer
    This tool is for educational purposes. Always verify suspicious URLs through multiple channels.
    """)
    
    # Main URL detection interface
    url_detection_page()

def url_detection_page():
    """Main URL detection interface."""
    st.header("🔍 URL Analysis")
    
    # Load model
    detector, model_type = load_model()
    if detector is None:
        st.error("No trained model found. Please run the training script first.")
        st.code("python3 phishshield_balanced.py", language="bash")
        return
    
    # Show model type
    if model_type == "Balanced":
        st.success("🎯 Using Balanced PhishShield Model (90.4% accuracy)")
    elif model_type == "Enhanced":
        st.success("🚀 Using Enhanced PhishShield Model (88.3% accuracy)")
    else:
        st.info("📊 Using Original PhishShield Model (83.5% accuracy)")
    
    # URL input
    col1, col2 = st.columns([3, 1])
    
    with col1:
        url_input = st.text_input(
            "Enter URL to analyze:",
            placeholder="https://example.com",
            help="Enter a URL to check if it's phishing or legitimate"
        )
    
    with col2:
        analyze_button = st.button("🔍 Analyze", type="primary")
    
    if analyze_button and url_input:
        if url_input.strip():
            try:
                with st.spinner("Analyzing URL..."):
                    # Use the correct method based on model type
                    if model_type == "Balanced":
                        result = detector.predict_balanced(url_input)
                    elif model_type == "Enhanced":
                        result = detector.predict_enhanced(url_input)
                    else:
                        result = detector.predict(url_input)
                
                # Display results
                st.subheader("Analysis Results")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    prediction_class = "phishing" if result['prediction'] == 'Phishing' else "legitimate"
                    st.markdown(f"""
                    <div class="prediction-box {prediction_class}">
                        <h3>Prediction: {result['prediction']}</h3>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    st.metric("Confidence", f"{result['confidence']:.1%}")
                
                with col3:
                    st.metric("Phishing Probability", f"{result['phishing_probability']:.1%}")
                
                # Detailed results
                st.subheader("Detailed Analysis")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**URL:**", result['url'])
                    st.write("**Prediction:**", result['prediction'])
                    st.write("**Confidence:**", f"{result['confidence']:.3f}")
                
                with col2:
                    st.write("**Phishing Probability:**", f"{result['phishing_probability']:.3f}")
                    st.write("**Legitimate Probability:**", f"{result['legitimate_probability']:.3f}")
                
                # Visualization
                fig, ax = plt.subplots(figsize=(8, 4))
                categories = ['Legitimate', 'Phishing']
                probabilities = [result['legitimate_probability'], result['phishing_probability']]
                colors = ['#4caf50', '#f44336']
                
                bars = ax.bar(categories, probabilities, color=colors, alpha=0.7)
                ax.set_ylabel('Probability')
                ax.set_title('Prediction Probabilities')
                ax.set_ylim(0, 1)
                
                # Add value labels on bars
                for bar, prob in zip(bars, probabilities):
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                           f'{prob:.3f}', ha='center', va='bottom')
                
                st.pyplot(fig)
                
            except Exception as e:
                st.error(f"Error analyzing URL: {str(e)}")
        else:
            st.warning("Please enter a valid URL.")
    
    # Example URLs
    st.subheader("Try These Example URLs")
    
    example_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://suspicious-site.com/secure-login?verify=account",
        "http://fake-bank.com/update-info",
        "https://www.microsoft.com",
        "https://phishing-example.com/login?redirect=bank.com"
    ]
    
    cols = st.columns(3)
    for i, url in enumerate(example_urls):
        with cols[i % 3]:
            if st.button(f"Test: {url[:30]}...", key=f"example_{i}"):
                st.session_state.example_url = url
                st.experimental_rerun()
    
    if hasattr(st.session_state, 'example_url'):
        st.text_input("Selected URL:", value=st.session_state.example_url, disabled=True)
        st.info("💡 Click 'Analyze' above to test this URL!")


if __name__ == "__main__":
    main()
