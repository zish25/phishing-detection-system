"""
Machine Learning model for phishing detection.
Production-ready implementation with comprehensive error handling and robustness.
Includes hybrid detection combining URL analysis + web content analysis + VirusTotal threat intelligence.
"""

import pickle
import os
import pandas as pd
import numpy as np
import logging
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from utils import extract_features, features_to_array, get_feature_names, normalize_url
from web_analyzer import WebAnalyzer
from virustotal_analyzer import VirusTotalAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishingDetectionModel:
    """Production-ready phishing detection model with comprehensive error handling."""

    def __init__(self, model_path='phishing_model.pkl'):
        self.model = None
        self.model_path = model_path
        self.is_trained = False
        self.metrics = {}

    def train(self, dataset_path='dataset.csv'):
        """
        Train the Random Forest model on the provided dataset.
        
        Args:
            dataset_path (str): Path to the CSV file containing training data
            
        Returns:
            dict: Training metrics (accuracy, precision, recall, f1) or None if failed
        """
        try:
            logger.info(f"Loading dataset from {dataset_path}...")
            
            if not os.path.exists(dataset_path):
                logger.error(f"Dataset file not found: {dataset_path}")
                return None
            
            df = pd.read_csv(dataset_path)
            logger.info(f"Dataset loaded: {len(df)} rows")
            
            if df.empty:
                logger.error("Dataset is empty")
                return None
            
            # Check required columns
            if 'url' not in df.columns or 'label' not in df.columns:
                logger.error("Dataset missing required columns: 'url' and/or 'label'")
                return None
            
            # Extract features
            logger.info("Extracting features from URLs...")
            X = []
            y = []
            
            for idx, row in df.iterrows():
                try:
                    url = row['url']
                    label = row['label']
                    
                    features = extract_features(url)
                    if features is not None:
                        X.append(features_to_array(features))
                        y.append(label)
                except Exception as e:
                    logger.debug(f"Error processing row {idx}: {e}")
                    continue
            
            if len(X) == 0:
                logger.error("No valid samples extracted from dataset")
                return None
            
            X = np.array(X, dtype=np.float64)
            y = np.array(y)
            
            logger.info(f"Extracted {len(X)} features")
            logger.info(f"Label distribution - Phishing: {sum(y)}, Legitimate: {len(y) - sum(y)}")
            
            # ---- TRAIN/TEST SPLIT ----
            logger.info("Splitting dataset (80/20)...")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # ---- TRAIN MODEL ----
            logger.info("Training Random Forest classifier...")
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                verbose=0
            )
            
            self.model.fit(X_train, y_train)
            logger.info("Model training completed")
            
            # ---- EVALUATION ----
            logger.info("Evaluating model on test set...")
            y_pred = self.model.predict(X_test)
            
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            self.metrics = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'test_size': len(y_test),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
            }
            
            self.is_trained = True
            
            # ---- SAVE MODEL ----
            self.save_model()
            
            # ---- PRINT RESULTS ----
            logger.info("\n" + "="*60)
            logger.info("MODEL EVALUATION RESULTS")
            logger.info("="*60)
            logger.info(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
            logger.info(f"Precision: {precision:.4f}")
            logger.info(f"Recall:    {recall:.4f}")
            logger.info(f"F1 Score:  {f1:.4f}")
            logger.info("="*60)
            
            return self.metrics
            
        except Exception as e:
            logger.error(f"Error during model training: {e}", exc_info=True)
            return None

    def save_model(self):
        """Save the trained model to disk."""
        try:
            if self.model is None:
                logger.error("Cannot save: Model is None")
                return False
            
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            
            logger.info(f"Model successfully saved to {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving model: {e}", exc_info=True)
            return False
    
    def load_model(self):
        """Load a trained model from disk."""
        try:
            if not os.path.exists(self.model_path):
                logger.error(f"Model file not found: {self.model_path}")
                logger.info("Please run 'python main.py' to train the model first")
                return False
            
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            self.is_trained = True
            logger.info(f"Model successfully loaded from {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading model: {e}", exc_info=True)
            self.model = None
            self.is_trained = False
            return False

    def predict(self, url):
        """
        Predict if a URL is phishing or legitimate.
        ALWAYS returns a valid prediction and confidence. Never returns None.
        Predictions are deterministic - same URL always produces same result.
        
        Args:
            url (str): The URL to predict
            
        Returns:
            tuple: (prediction, confidence_score) where:
                prediction: 0 (safe) or 1 (phishing)
                confidence: float between 0.5 and 1.0
        """
        try:
            # ---- PHASE 1: Model Validation ----
            if self.model is None:
                logger.info("Model not in memory, attempting to load...")
                self.load_model()

            if self.model is None:
                logger.error("Model failed to load. Returning safe default.")
                return 0, 0.55  # Conservative: default to SAFE with low confidence

            # ---- PHASE 2: Input Validation & Normalization ----
            if not url or not isinstance(url, str):
                logger.warning(f"Invalid URL input: {url}")
                return 0, 0.51  # SAFE with minimal confidence

            url = url.strip()
            if len(url) == 0:
                logger.warning("Empty URL provided")
                return 0, 0.51

            # Normalize URL for consistency
            url_normalized = normalize_url(url)
            logger.info(f"Predicting URL (original: {url} → normalized: {url_normalized})")

            # ---- PHASE 3: Feature Extraction with Fallback ----
            features = extract_features(url_normalized)
            
            if features is None:
                logger.warning(f"Feature extraction failed for URL: {url_normalized}")
                return 0, 0.52  # SAFE with minimal confidence

            # Validate features dictionary
            if not isinstance(features, dict) or len(features) == 0:
                logger.warning(f"Invalid features returned for URL: {url_normalized}")
                return 0, 0.52

            # ---- PHASE 4: Convert Features to Array ----
            try:
                feature_array = features_to_array(features)
                
                # Validate array
                if feature_array is None or len(feature_array) == 0:
                    logger.warning("Features array is empty")
                    return 0, 0.52
                
                # Check for NaN or invalid values
                feature_array = np.array(feature_array, dtype=np.float64)
                
                if np.any(np.isnan(feature_array)) or np.any(np.isinf(feature_array)):
                    logger.warning(f"Invalid values in feature array: {feature_array}")
                    return 0, 0.52
                
                # Log features used for prediction (for debugging consistency)
                feature_names = get_feature_names()
                logger.debug("=" * 70)
                logger.debug("FEATURES USED FOR PREDICTION:")
                logger.debug("=" * 70)
                for name, value in zip(feature_names, feature_array):
                    logger.debug(f"  {name:30s}: {value:10.4f}")
                logger.debug("=" * 70)
                
                # Reshape for model prediction
                X = feature_array.reshape(1, -1)
                
            except Exception as e:
                logger.error(f"Error converting features to array: {e}")
                return 0, 0.52

            # ---- PHASE 5: Model Prediction (Deterministic) ----
            try:
                prediction = self.model.predict(X)[0]
                confidence_array = self.model.predict_proba(X)[0]
                confidence = float(max(confidence_array))
                
                # Validate prediction output
                if prediction not in [0, 1]:
                    logger.error(f"Invalid prediction value: {prediction}")
                    return 0, 0.52
                
                if not (0.5 <= confidence <= 1.0):
                    logger.warning(f"Confidence out of range: {confidence}, clamping...")
                    confidence = max(0.5, min(1.0, confidence))
                
                # ---- PHASE 6: Domain Reputation Check (False Positive Reduction) ----
                # Reduce risk for trusted domains to prevent false positives
                trusted_domains = [
                    'github.com', 'github.io',
                    'google.com', 'accounts.google.com', 'mail.google.com', 'drive.google.com',
                    'microsoft.com', 'office.com', 'outlook.com', 'hotmail.com',
                    'amazon.com', 'aws.amazon.com',
                    'apple.com', 'icloud.com',
                    'facebook.com', 'instagram.com', 'whatsapp.com',
                    'twitter.com', 'x.com',
                    'linkedin.com',
                    'youtube.com',
                    'wikipedia.org',
                    'stackoverflow.com',
                    'reddit.com',
                    'wordpress.com',
                    'blogger.com',
                    'pinterest.com',
                    'dropbox.com',
                    'evernote.com',
                    'notion.so',
                    'slack.com',
                    'discord.com',
                    'telegram.org',
                    'skype.com',
                    'zoom.us',
                    'webex.com'
                ]
                
                parsed_url = urlparse(url_normalized)
                domain = parsed_url.netloc.lower().replace('www.', '')
                
                # Check if domain is trusted or subdomain of trusted domain
                is_trusted = any(domain == td or domain.endswith('.' + td) for td in trusted_domains)
                
                if is_trusted:
                    logger.info(f"✓ Domain '{domain}' is in trusted list - reducing false positive risk")
                    
                    # For trusted domains: heavily bias toward SAFE
                    if prediction == 1:  # Model predicted PHISHING
                        logger.info(f"Model predicted PHISHING for trusted domain - overriding to SAFE")
                        prediction = 0
                        # Set confidence to the safe probability from the model
                        confidence = float(confidence_array[0])
                    else:
                        # Already predicted safe, boost confidence
                        confidence = max(confidence, 0.95)
                
                status = "🔴 PHISHING" if prediction == 1 else "🟢 SAFE"
                logger.info(f"FINAL PREDICTION: {status} | Confidence: {confidence*100:.1f}%")
                logger.info(f"Probability distribution: Safe={confidence_array[0]*100:.1f}%, Phishing={confidence_array[1]*100:.1f}%")
                
                return int(prediction), confidence
                
            except Exception as e:
                logger.error(f"Sklearn prediction error: {e}")
                return 0, 0.52

        except Exception as e:
            logger.exception(f"Unexpected error in predict(): {e}")
            return 0, 0.52  # SAFE with minimal confidence (safety fallback)

    def predict_hybrid(self, url: str, use_content_analysis: bool = True, vt_api_key: str = None):
        """
        Advanced hybrid prediction combining multiple threat intelligence sources.
        Combines: URL analysis + web content analysis + VirusTotal threat intelligence
        
        Args:
            url (str): The URL to predict
            use_content_analysis (bool): Whether to analyze webpage content
            vt_api_key (str): VirusTotal API key for threat intelligence
            
        Returns:
            dict: Comprehensive analysis result with multi-source predictions
        """
        # Normalize URL first
        url_normalized = normalize_url(url)
        
        result = {
            'url': url_normalized,
            'original_url': url,
            'url_prediction': 0,
            'url_confidence': 0.5,
            'web_risk_score': 0.5,
            'virustotal_score': 0.5,
            'external_threat_intelligence': 0.5,
            'final_prediction': 0,
            'final_confidence': 0.5,
            'reasoning': [],
            'web_analysis': None,
            'virustotal_analysis': None,
            'is_phishing': False,
            'analysis_method': 'url_only'
        }
        
        try:
            logger.info(f"\n{'='*70}")
            logger.info(f"ADVANCED HYBRID ANALYSIS WITH EXTERNAL THREAT INTELLIGENCE")
            logger.info(f"Original URL: {url}")
            logger.info(f"Normalized URL: {url_normalized}")
            logger.info(f"{'='*70}")
            
            # Step 1: URL-based prediction (deterministic)
            logger.info("Step 1: URL-based ML analysis...")
            url_pred, url_conf = self.predict(url_normalized)
            result['url_prediction'] = url_pred
            result['url_confidence'] = url_conf
            
            # Step 2: Web content analysis (optional)
            if use_content_analysis and url_normalized.startswith('http'):
                logger.info("Step 2: Web content analysis...")
                try:
                    web_analyzer = WebAnalyzer(timeout=15)
                    web_analysis = web_analyzer.analyze_url(url_normalized)
                    result['web_analysis'] = web_analysis
                    
                    if web_analysis.get('success'):
                        web_risk = web_analysis.get('risk_score', 0.5)
                        result['web_risk_score'] = web_risk
                        result['analysis_method'] = 'hybrid_url_and_content'
                        result['reasoning'].extend(web_analysis.get('indicators', []))
                        logger.info(f"Web analysis: {web_risk*100:.1f}% risk")
                    else:
                        logger.warning(f"Web analysis failed")
                except Exception as e:
                    logger.error(f"Web content analysis error: {e}")
            
            # Step 3: VirusTotal threat intelligence
            logger.info("Step 3: Fetching external threat intelligence (VirusTotal)...")
            vt_analyzer = VirusTotalAnalyzer(api_key=vt_api_key)
            
            if vt_analyzer.is_configured():
                try:
                    # Get existing report (faster, uses cache)
                    vt_analysis = vt_analyzer.get_url_report(url_normalized)
                    result['virustotal_analysis'] = vt_analysis
                    
                    if vt_analysis.get('success'):
                        vt_score = vt_analysis.get('malicious_score', 0.5)
                        result['virustotal_score'] = vt_score
                        result['external_threat_intelligence'] = vt_score
                        result['analysis_method'] = 'full_threat_intelligence'
                        
                        # Add VirusTotal findings to reasoning
                        summary = vt_analysis.get('detection_summary', '')
                        if summary:
                            result['reasoning'].append(f"🔍 VirusTotal: {summary}")
                        
                        logger.info(f"VirusTotal scan: {vt_score*100:.1f}% malicious")
                    else:
                        error_msg = vt_analysis.get('error', 'Unknown error')
                        logger.info(f"VirusTotal analysis unavailable: {error_msg}")
                        result['reasoning'].append(f"⚠️ VirusTotal: {error_msg}")
                        
                except Exception as e:
                    logger.error(f"VirusTotal analysis error: {e}")
                    result['reasoning'].append(f"⚠️ VirusTotal check failed: {str(e)}")
            else:
                logger.info("VirusTotal API not configured - skipping threat intelligence")
                result['reasoning'].append("ℹ️ VirusTotal API not configured (optional)")
            
            # Step 4: Combine all predictions with dynamic weighting
            logger.info("Step 4: Combining all threat intelligence sources...")
            
            # Calculate weights based on available sources
            if result['web_analysis'] and result['web_analysis'].get('success'):
                if result['virustotal_analysis'] and result['virustotal_analysis'].get('success'):
                    # All sources available: URL 40%, Web 30%, VirusTotal 30%
                    combined_score = (url_conf * 0.40) + (result['web_risk_score'] * 0.30) + (result['virustotal_score'] * 0.30)
                    result['analysis_method'] = 'full_threat_intelligence'
                    logger.info(f"Score: URL({url_conf:.2f}*0.40) + Web({result['web_risk_score']:.2f}*0.30) + VT({result['virustotal_score']:.2f}*0.30)")
                else:
                    # URL + Web: 60% / 40%
                    combined_score = (url_conf * 0.60) + (result['web_risk_score'] * 0.40)
                    logger.info(f"Score: URL({url_conf:.2f}*0.60) + Web({result['web_risk_score']:.2f}*0.40)")
            else:
                if result['virustotal_analysis'] and result['virustotal_analysis'].get('success'):
                    # URL + VirusTotal: 50% / 50%
                    combined_score = (url_conf * 0.50) + (result['virustotal_score'] * 0.50)
                    result['analysis_method'] = 'url_and_threat_intelligence'
                    logger.info(f"Score: URL({url_conf:.2f}*0.50) + VT({result['virustotal_score']:.2f}*0.50)")
                else:
                    # URL only
                    combined_score = url_conf
                    logger.info(f"Score: URL only ({url_conf:.2f})")
            
            result['final_confidence'] = combined_score
            result['final_prediction'] = 1 if combined_score >= 0.65 else 0
            result['is_phishing'] = result['final_prediction'] == 1
            
            # Add reasoning summary
            if url_pred == 1:
                result['reasoning'].insert(0, f"🚨 URL pattern analysis: Phishing indicators ({url_conf*100:.1f}% confidence)")
            else:
                result['reasoning'].insert(0, f"✓ URL pattern analysis: Legitimate appearance ({url_conf*100:.1f}% confidence)")
            
            # Add external threat intelligence summary
            if result['external_threat_intelligence'] < 0.5:
                result['reasoning'].append(f"✓ External threat intelligence: Low risk ({result['external_threat_intelligence']*100:.1f}%)")
            else:
                result['reasoning'].append(f"⚠️ External threat intelligence: High risk ({result['external_threat_intelligence']*100:.1f}%)")
            
            final_status = "🔴 PHISHING" if result['is_phishing'] else "🟢 LEGITIMATE"
            logger.info(f"\n{'='*70}")
            logger.info(f"FINAL PREDICTION: {final_status}")
            logger.info(f"Analysis Sources: {result['analysis_method']}")
            logger.info(f"Combined Risk Score: {combined_score*100:.1f}%")
            logger.info(f"URL: {url_conf*100:.1f}% | Web: {result['web_risk_score']*100:.1f}% | VT: {result['external_threat_intelligence']*100:.1f}%")
            logger.info(f"{'='*70}\n")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in hybrid prediction: {e}", exc_info=True)
            result['reasoning'].append(f"⚠️ Analysis error: {str(e)}")
            result['analysis_method'] = 'error_fallback'
            return result

    def get_feature_importance(self):
        """
        Get feature importances from the trained model.
        
        Returns:
            dict: Feature names and their importance scores, or None if model not available
        """
        try:
            if self.model is None:
                logger.warning("Model is None, cannot get feature importance")
                return None

            feature_names = get_feature_names()
            
            if not hasattr(self.model, 'feature_importances_'):
                logger.error("Model does not have feature_importances_ attribute")
                return None
            
            importances = self.model.feature_importances_
            
            if importances is None or len(importances) == 0:
                logger.warning("Feature importances are empty")
                return None
            
            importance_dict = dict(zip(feature_names, importances))
            logger.info(f"Retrieved feature importances for {len(importance_dict)} features")
            return importance_dict
            
        except Exception as e:
            logger.error(f"Error getting feature importance: {e}", exc_info=True)
            return None
    
    def get_metrics(self):
        """
        Get the latest training metrics.
        
        Returns:
            dict: Dictionary containing accuracy, precision, recall, f1_score
        """
        if not self.metrics:
            logger.warning("No metrics available. Model may not have been trained yet.")
            return {}
        
        return self.metrics.copy()  # Return a copy to prevent external modifications
    
    def is_ready(self):
        """
        Check if the model is ready for predictions.
        
        Returns:
            bool: True if model is loaded and ready, False otherwise
        """
        return self.model is not None and self.is_trained
    
    def health_check(self):
        """
        Perform a health check on the model.
        
        Returns:
            dict: Health status information
        """
        try:
            status = {
                'model_loaded': self.model is not None,
                'model_trained': self.is_trained,
                'model_file_exists': os.path.exists(self.model_path),
                'has_metrics': len(self.metrics) > 0,
                'metrics_accuracy': self.metrics.get('accuracy', 'N/A')
            }
            return status
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {'error': str(e)}
