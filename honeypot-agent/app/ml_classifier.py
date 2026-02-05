"""
ML-based Scam Classifier Module.
Uses TF-IDF + Multinomial Naive Bayes trained on Indian banking/UPI scam patterns.
"""

import os
import re
import pickle
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from .config import logger

# Labels
LABEL_LEGIT = 0
LABEL_SUSPICIOUS = 1
LABEL_SCAM = 2

LABEL_NAMES = {0: "legit", 1: "suspicious", 2: "scam"}


class ScamClassifier:
    """
    ML-based scam classifier using TF-IDF + Naive Bayes.
    Provides probability scores for confidence-based decision making.
    """

    def __init__(self):
        self.model: Optional[Pipeline] = None
        self.is_trained = False
        self.model_path = Path(__file__).parent.parent / "data" / "scam_model.pkl"
        self.dataset_path = Path(__file__).parent.parent / "data" / "scam_dataset_500.csv"

        # Try to load existing model or train new one
        self._initialize_model()

    def _initialize_model(self):
        """Initialize the model - load from file or train fresh."""
        # Try to load pre-trained model
        if self.model_path.exists():
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                self.is_trained = True
                logger.info("Loaded pre-trained scam classifier model")
                return
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")

        # Train new model if dataset exists
        if self.dataset_path.exists():
            self._train_model()
        else:
            logger.warning("No dataset found - classifier will use fallback mode")

    def _train_model(self):
        """Train the model on the dataset."""
        try:
            logger.info("Training scam classifier model...")

            # Load dataset
            df = pd.read_csv(self.dataset_path)
            X = df['text'].values
            y = df['label'].values

            # Create pipeline with TF-IDF + Naive Bayes
            self.model = Pipeline([
                ('tfidf', TfidfVectorizer(
                    max_features=5000,
                    ngram_range=(1, 2),  # Unigrams and bigrams
                    stop_words='english',
                    lowercase=True
                )),
                ('classifier', MultinomialNB(alpha=0.1))
            ])

            # Train on full dataset (small dataset, no need for train/test split in prod)
            self.model.fit(X, y)
            self.is_trained = True

            # Save model
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)

            logger.info(f"Model trained successfully on {len(X)} samples")

        except Exception as e:
            logger.error(f"Failed to train model: {e}")
            self.is_trained = False

    def predict_proba(self, text: str) -> Dict[str, float]:
        """
        Get probability scores for each class.

        Args:
            text: Input message text

        Returns:
            Dict with probabilities: {legit, suspicious, scam, confidence}
        """
        if not self.is_trained or not self.model:
            # Fallback: return neutral probabilities
            return {
                "legit": 0.33,
                "suspicious": 0.34,
                "scam": 0.33,
                "confidence": 0.34
            }

        try:
            probs = self.model.predict_proba([text])[0]

            return {
                "legit": float(probs[0]),
                "suspicious": float(probs[1]),
                "scam": float(probs[2]),
                "confidence": float(max(probs))
            }
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return {
                "legit": 0.33,
                "suspicious": 0.34,
                "scam": 0.33,
                "confidence": 0.34
            }

    def classify(self, text: str) -> Tuple[str, float]:
        """
        Classify text and return label with confidence.

        Args:
            text: Input message text

        Returns:
            Tuple of (label_name, confidence)
        """
        probs = self.predict_proba(text)

        # Decision logic based on confidence thresholds
        if probs["scam"] > 0.75:
            return ("scam", probs["scam"])
        elif probs["suspicious"] > 0.6:
            return ("suspicious", probs["suspicious"])
        else:
            return ("legit", probs["legit"])


# Singleton instance
scam_classifier = ScamClassifier()


def get_ml_prediction(text: str) -> Dict[str, float]:
    """Get ML probability scores for text."""
    return scam_classifier.predict_proba(text)


def classify_message(text: str) -> Tuple[str, float]:
    """Classify message and return (label, confidence)."""
    return scam_classifier.classify(text)
