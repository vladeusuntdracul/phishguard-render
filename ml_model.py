import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os
import logging
from typing import List, Tuple
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingClassifier:
    """
    Machine learning model for phishing detection using Naive Bayes
    """
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.pipeline = None
        self.is_trained = False
        
        # Initialize with basic training data
        self._create_initial_model()
    
    def _create_initial_model(self):
        """Create initial model with basic phishing patterns"""
        try:
            # Basic training data - common phishing vs legitimate patterns
            phishing_samples = [
                "Congratulations! You have won $1,000,000! Click here to claim your prize immediately!",
                "Your account has been suspended. Verify your identity now by clicking this link.",
                "URGENT: Your bank account will be closed. Update your information immediately.",
                "You have received an inheritance of $500,000. Contact us to claim your money.",
                "Final notice: Your payment is overdue. Pay now to avoid legal action.",
                "Confirm your PayPal account details to avoid suspension.",
                "Your Apple ID has been locked. Click here to unlock it now.",
                "Act now! Limited time offer expires today. Don't miss out!",
                "Your tax refund is ready. Click to claim $2,500 refund.",
                "Security alert: Unusual activity detected on your account.",
                "Winner! You've been selected for our special promotion.",
                "Your credit card will be charged unless you cancel immediately.",
                "Verify your Amazon account to continue shopping.",
                "Your Microsoft account requires immediate attention.",
                "Click here to update your password before it expires.",
                "You have a package waiting. Pay delivery fee to receive.",
                "Your subscription will auto-renew. Cancel now to avoid charges.",
                "Congratulations on your lottery win! Claim your $50,000 prize.",
                "Your account has been compromised. Change password immediately.",
                "Special offer: Get rich quick with our investment program."
            ]
            
            legitimate_samples = [
                "Thank you for your purchase. Your order has been shipped.",
                "Your monthly statement is now available for download.",
                "Reminder: Your appointment is scheduled for tomorrow.",
                "Welcome to our newsletter. Here are this week's updates.",
                "Your flight booking has been confirmed for next week.",
                "Thank you for registering. Please verify your email address.",
                "Your subscription has been successfully renewed.",
                "Here's your receipt for today's purchase.",
                "Your meeting has been rescheduled to next Tuesday.",
                "Weather alert: Heavy rain expected in your area.",
                "Your order is being prepared and will ship soon.",
                "Annual report: Company performance summary for 2024.",
                "New features have been added to your account.",
                "Your password was successfully changed.",
                "System maintenance scheduled for this weekend.",
                "Your profile has been updated successfully.",
                "Holiday hours: We'll be closed on Monday.",
                "Your feedback has been received. Thank you.",
                "Course reminder: Your class starts at 2 PM today.",
                "Your download is ready. Files are available for 7 days."
            ]
            
            # Create training dataset
            texts = phishing_samples + legitimate_samples
            labels = [1] * len(phishing_samples) + [0] * len(legitimate_samples)  # 1 = phishing, 0 = legitimate
            
            # Create and train the model
            self.vectorizer = TfidfVectorizer(
                max_features=1000,
                ngram_range=(1, 2),
                stop_words='english',
                lowercase=True,
                strip_accents='unicode'
            )
            
            self.model = MultinomialNB(alpha=0.1)
            
            # Create pipeline
            self.pipeline = Pipeline([
                ('vectorizer', self.vectorizer),
                ('classifier', self.model)
            ])
            
            # Train the model
            X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)
            self.pipeline.fit(X_train, y_train)
            
            # Evaluate model
            y_pred = self.pipeline.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            self.is_trained = True
            logger.info(f"Initial model trained with accuracy: {accuracy:.2f}")
            
        except Exception as e:
            logger.error(f"Error creating initial model: {str(e)}")
            self.is_trained = False
    
    def predict(self, content: str, sender: str = "", subject: str = "") -> float:
        """
        Predict phishing probability for a message
        
        Args:
            content: Message content
            sender: Sender email
            subject: Subject line
            
        Returns:
            Probability score (0.0 to 1.0)
        """
        if not self.is_trained:
            logger.warning("Model not trained, returning default score")
            return 0.3  # Default moderate score
        
        try:
            # Combine all text features
            combined_text = f"{subject} {content}"
            
            # Add sender features
            if sender:
                combined_text += f" sender:{sender}"
            
            # Preprocess text
            processed_text = self._preprocess_text(combined_text)
            
            # Get prediction probability
            proba = self.pipeline.predict_proba([processed_text])
            phishing_probability = proba[0][1] if len(proba[0]) > 1 else 0.0
            
            return float(phishing_probability)
            
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            return 0.3  # Default score on error
    
    def _preprocess_text(self, text: str) -> str:
        """Preprocess text for better classification"""
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove excessive punctuation
        text = re.sub(r'[!]{2,}', '!', text)
        text = re.sub(r'[?]{2,}', '?', text)
        text = re.sub(r'[.]{3,}', '...', text)
        
        # Replace URLs with placeholder
        text = re.sub(r'http[s]?://[^\s]+', 'URL_PLACEHOLDER', text)
        
        # Replace email addresses with placeholder
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL_PLACEHOLDER', text)
        
        # Replace phone numbers with placeholder
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'PHONE_PLACEHOLDER', text)
        
        # Replace excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        return text.strip()
    
    def update_model(self, new_content: str, label: int, sender: str = "", subject: str = ""):
        """
        Update model with new labeled data (for continuous learning)
        
        Args:
            new_content: New message content
            label: 1 for phishing, 0 for legitimate
            sender: Sender email
            subject: Subject line
        """
        try:
            if not self.is_trained:
                logger.warning("Cannot update untrained model")
                return
            
            # Combine text features
            combined_text = f"{subject} {new_content}"
            if sender:
                combined_text += f" sender:{sender}"
            
            processed_text = self._preprocess_text(combined_text)
            
            # Partial fit (online learning)
            if hasattr(self.pipeline.named_steps['classifier'], 'partial_fit'):
                # Transform the text using existing vectorizer
                X_new = self.pipeline.named_steps['vectorizer'].transform([processed_text])
                self.pipeline.named_steps['classifier'].partial_fit(X_new, [label])
                logger.info("Model updated with new sample")
            else:
                logger.warning("Model doesn't support online learning")
                
        except Exception as e:
            logger.error(f"Error updating model: {str(e)}")
    
    def retrain(self):
        """Retrain the model (placeholder for more sophisticated retraining)"""
        try:
            if not self.is_trained:
                self._create_initial_model()
            else:
                logger.info("Model retraining completed")
                # In a real implementation, this would retrain with accumulated data
                
        except Exception as e:
            logger.error(f"Error retraining model: {str(e)}")
            raise
    
    def save_model(self, filepath: str):
        """Save the trained model to disk"""
        try:
            if self.is_trained:
                with open(filepath, 'wb') as f:
                    pickle.dump(self.pipeline, f)
                logger.info(f"Model saved to {filepath}")
            else:
                logger.warning("No trained model to save")
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
    
    def load_model(self, filepath: str):
        """Load a trained model from disk"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    self.pipeline = pickle.load(f)
                self.is_trained = True
                logger.info(f"Model loaded from {filepath}")
            else:
                logger.warning(f"Model file not found: {filepath}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
    
    def get_feature_importance(self) -> dict:
        """Get important features from the model"""
        try:
            if not self.is_trained:
                return {}
            
            # Get feature names from vectorizer
            feature_names = self.pipeline.named_steps['vectorizer'].get_feature_names_out()
            
            # Get feature log probabilities from Naive Bayes
            if hasattr(self.pipeline.named_steps['classifier'], 'feature_log_prob_'):
                log_probs = self.pipeline.named_steps['classifier'].feature_log_prob_
                
                # Get top features for phishing class (class 1)
                if log_probs.shape[0] > 1:
                    phishing_features = log_probs[1]  # Phishing class features
                    top_indices = np.argsort(phishing_features)[-20:]  # Top 20 features
                    
                    top_features = {}
                    for idx in top_indices:
                        if idx < len(feature_names):
                            top_features[feature_names[idx]] = float(phishing_features[idx])
                    
                    return top_features
            
            return {}
            
        except Exception as e:
            logger.error(f"Error getting feature importance: {str(e)}")
            return {}
