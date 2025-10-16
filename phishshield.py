"""
PhishShield - Intelligent Phishing URL Detection System
Core detection module with URL feature extraction and prediction capabilities.
"""

import pandas as pd
import numpy as np
import re
import joblib
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')


class PhishShieldDetector:
    """
    Main class for phishing URL detection using machine learning.
    """
    
    def __init__(self, model_path=None):
        """
        Initialize the PhishShield detector.
        
        Args:
            model_path (str): Path to pre-trained model file
        """
        self.model = None
        self.feature_names = None
        
        if model_path:
            self.load_model(model_path)
    
    def extract_url_features(self, url):
        """
        Extract features from a URL for phishing detection.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            list: Extracted features
        """
        features = []
        
        # Basic URL features
        features.append(len(url))  # URL length
        
        # Count special characters
        features.append(url.count('.'))  # Number of dots
        features.append(url.count('-'))  # Number of hyphens
        features.append(url.count('_'))  # Number of underscores
        features.append(url.count('/'))  # Number of forward slashes
        features.append(url.count('?'))  # Number of question marks
        features.append(url.count('='))  # Number of equals signs
        features.append(url.count('@'))  # Number of @ symbols
        features.append(url.count('&'))  # Number of ampersands
        features.append(url.count('#'))  # Number of hash symbols
        features.append(url.count('%'))  # Number of percent symbols
        
        # Protocol features
        features.append(1 if url.startswith('https://') else 0)  # HTTPS
        features.append(1 if url.startswith('http://') else 0)   # HTTP
        
        # Domain features
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Domain length
            features.append(len(domain))
            
            # Number of subdomains
            features.append(domain.count('.'))
            
            # Check for suspicious patterns
            features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0)  # IP address
            features.append(1 if re.search(r'[0-9]', domain) else 0)  # Numbers in domain
            
            # Suspicious keywords
            suspicious_keywords = ['secure', 'account', 'update', 'verify', 'confirm', 'login', 'signin']
            features.append(sum(1 for keyword in suspicious_keywords if keyword in url.lower()))
            
            # Path features
            path = parsed.path
            features.append(len(path))
            features.append(path.count('/'))
            
            # Query features
            query = parsed.query
            features.append(len(query))
            features.append(query.count('&'))
            
        except:
            # If URL parsing fails, use default values
            features.extend([0] * 8)
        
        # Additional heuristic features
        features.append(1 if 'www.' in url.lower() else 0)  # Contains www
        features.append(1 if url.count('.') > 3 else 0)  # Too many dots
        features.append(1 if len(url) > 75 else 0)  # Very long URL
        
        # Character frequency features
        features.append(url.count('a') + url.count('A'))  # Count of 'a'
        features.append(url.count('e') + url.count('E'))  # Count of 'e'
        features.append(url.count('i') + url.count('I'))  # Count of 'i'
        features.append(url.count('o') + url.count('O'))  # Count of 'o'
        features.append(url.count('u') + url.count('U'))  # Count of 'u'
        
        return features
    
    def get_feature_names(self):
        """
        Get the names of all features used in the model.
        
        Returns:
            list: Feature names
        """
        return [
            'url_length', 'dots', 'hyphens', 'underscores', 'slashes', 'question_marks',
            'equals', 'at_symbols', 'ampersands', 'hashes', 'percent_symbols',
            'https', 'http', 'domain_length', 'subdomains', 'ip_address', 'numbers_in_domain',
            'suspicious_keywords', 'path_length', 'path_slashes', 'query_length',
            'query_ampersands', 'contains_www', 'too_many_dots', 'very_long_url',
            'count_a', 'count_e', 'count_i', 'count_o', 'count_u'
        ]
    
    def train_model(self, X, y, test_size=0.2, random_state=42):
        """
        Train the RandomForest model.
        
        Args:
            X (array-like): Feature matrix
            y (array-like): Target labels
            test_size (float): Proportion of data for testing
            random_state (int): Random seed for reproducibility
        """
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Train the model
        self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=random_state,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model trained successfully!")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Training samples: {len(X_train)}")
        print(f"Test samples: {len(X_test)}")
        
        return X_test, y_test, y_pred
    
    def predict(self, url):
        """
        Predict if a URL is phishing or legitimate.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Prediction result with confidence
        """
        if self.model is None:
            raise ValueError("Model not loaded. Please train or load a model first.")
        
        # Extract features
        features = self.extract_url_features(url)
        features_array = np.array(features).reshape(1, -1)
        
        # Make prediction
        prediction = self.model.predict(features_array)[0]
        probabilities = self.model.predict_proba(features_array)[0]
        
        # Get confidence
        confidence = max(probabilities)
        
        result = {
            'url': url,
            'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
            'confidence': confidence,
            'phishing_probability': probabilities[1],
            'legitimate_probability': probabilities[0]
        }
        
        return result
    
    def save_model(self, filepath):
        """
        Save the trained model to a file.
        
        Args:
            filepath (str): Path to save the model
        """
        if self.model is None:
            raise ValueError("No model to save. Please train a model first.")
        
        model_data = {
            'model': self.model,
            'feature_names': self.get_feature_names()
        }
        
        joblib.dump(model_data, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """
        Load a pre-trained model from a file.
        
        Args:
            filepath (str): Path to the model file
        """
        model_data = joblib.load(filepath)
        self.model = model_data['model']
        self.feature_names = model_data['feature_names']
        print(f"Model loaded from {filepath}")
    
    def get_feature_importance(self):
        """
        Get feature importance from the trained model.
        
        Returns:
            pandas.DataFrame: Feature importance scores
        """
        if self.model is None:
            raise ValueError("No trained model available.")
        
        importance_df = pd.DataFrame({
            'feature': self.get_feature_names(),
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        return importance_df


def load_uci_dataset():
    """
    Load and preprocess the UCI Phishing Websites Dataset.
    This function simulates loading the dataset since we'll create synthetic data
    for demonstration purposes.
    
    Returns:
        tuple: (X, y) feature matrix and target labels
    """
    print("Loading UCI Phishing Websites Dataset...")
    
    # For demonstration, we'll create synthetic data that mimics the UCI dataset
    # In a real implementation, you would load the actual CSV file
    np.random.seed(42)
    n_samples = 1000
    
    # Generate synthetic features (30 features as in the UCI dataset)
    X = np.random.rand(n_samples, 30)
    
    # Generate synthetic labels (0 = legitimate, 1 = phishing)
    # Make it somewhat realistic by correlating certain features with phishing
    y = np.zeros(n_samples)
    
    # Higher values of certain features increase phishing probability
    phishing_prob = (
        X[:, 0] * 0.1 +  # URL length
        X[:, 1] * 0.2 +  # Number of dots
        X[:, 5] * 0.3 +  # Question marks
        X[:, 7] * 0.4 +  # @ symbols
        np.random.rand(n_samples) * 0.2
    )
    
    y[phishing_prob > 0.5] = 1
    
    print(f"Dataset loaded: {n_samples} samples, {X.shape[1]} features")
    print(f"Phishing samples: {sum(y)} ({sum(y)/len(y)*100:.1f}%)")
    print(f"Legitimate samples: {len(y)-sum(y)} ({(len(y)-sum(y))/len(y)*100:.1f}%)")
    
    return X, y


if __name__ == "__main__":
    # Example usage
    detector = PhishShieldDetector()
    
    # Load and train on dataset
    X, y = load_uci_dataset()
    X_test, y_test, y_pred = detector.train_model(X, y)
    
    # Save the model
    detector.save_model('model.pkl')
    
    # Test prediction
    test_urls = [
        "https://www.google.com",
        "https://suspicious-site.com/secure-login?verify=account",
        "https://www.github.com",
        "http://fake-bank.com/update-info"
    ]
    
    print("\n" + "="*50)
    print("TESTING PREDICTIONS")
    print("="*50)
    
    for url in test_urls:
        result = detector.predict(url)
        print(f"\nURL: {url}")
        print(f"Prediction: {result['prediction']}")
        print(f"Confidence: {result['confidence']:.3f}")
        print(f"Phishing Probability: {result['phishing_probability']:.3f}")
    
    # Show feature importance
    print("\n" + "="*50)
    print("TOP 10 MOST IMPORTANT FEATURES")
    print("="*50)
    importance_df = detector.get_feature_importance()
    print(importance_df.head(10))
