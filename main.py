"""
Main entry point for training and evaluating the phishing detection model.
Demonstrates both basic URL analysis and advanced hybrid web analysis.
"""

import pandas as pd
import numpy as np
from sklearn import metrics
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix

from model import PhishingDetectionModel
from visualize import plot_accuracy, plot_confusion_matrix, plot_feature_importance, plot_metrics


def main():
    """
    Main function to train the model and generate visualizations.
    Demonstrates both URL-based and hybrid predictions.
    """
    print("\n" + "="*70)
    print("AI-POWERED PHISHING DETECTION SYSTEM (ADVANCED)")
    print("="*70 + "\n")
    
    # Initialize model
    model = PhishingDetectionModel()
    
    # Train the model
    print("STEP 1: Training the model...")
    print("-" * 70)
    metrics = model.train('dataset.csv')
    
    if metrics is None:
        print("Failed to train model. Please check dataset.csv")
        return
    
    print("\nSTEP 2: Generating visualizations...")
    print("-" * 70)
    
    # Generate visualizations
    plot_accuracy(metrics['accuracy'], 'accuracy.png')
    y_test = metrics.get('y_test', [0, 1])
    y_pred = metrics.get('y_pred', [0, 1])

    plot_confusion_matrix(y_test, y_pred, 'confusion_matrix.png')
    
    # Get and plot feature importance
    feature_importance = model.get_feature_importance()
    if feature_importance:
        plot_feature_importance(feature_importance, 'feature_importance.png')
    
    # Plot all metrics
    plot_metrics(metrics, 'metrics.png')
    
    print("\nSTEP 3: Model ready for predictions!")
    print("-" * 70)
    
    # Test with sample URLs using BASIC prediction
    print("\n📊 BASIC URL-BASED PREDICTIONS:")
    print("-" * 70)
    
    basic_test_urls = [
        "https://www.google.com",
        "http://bit.ly/malicious",
        "https://secure-paypal-verify.com/update",
        "https://github.com"
    ]
    
    for url in basic_test_urls:
        prediction, confidence = model.predict(url)
        status = "🔴 PHISHING" if prediction == 1 else "🟢 SAFE"
        print(f"URL: {url}")
        print(f"Status: {status}")
        print(f"Confidence: {confidence*100:.2f}%\n")
    
    # Test with sample URLs using HYBRID prediction (URL + Content Analysis)
    print("\n🔍 ADVANCED HYBRID PREDICTIONS (URL + Content Analysis):")
    print("-" * 70)
    
    hybrid_test_urls = [
        "https://www.github.com",
        "https://www.google.com",
    ]
    
    for url in hybrid_test_urls:
        print(f"\nAnalyzing: {url}")
        print("-" * 70)
        
        try:
            result = model.predict_hybrid(url, use_content_analysis=True)
            
            print(f"URL Prediction: {'Phishing' if result['url_prediction'] == 1 else 'Legitimate'} ({result['url_confidence']*100:.1f}%)")
            
            if result['web_analysis'] and result['web_analysis'].get('success'):
                print(f"Web Risk Score: {result['web_risk_score']*100:.1f}%")
                print(f"External Links: {len(result['web_analysis'].get('external_links', []))}")
                print(f"Suspicious Links: {len(result['web_analysis'].get('suspicious_links', []))}")
                print(f"Forms Detected: {len(result['web_analysis'].get('forms', []))}")
            
            print(f"\n✓ Final Prediction: {'🔴 PHISHING' if result['is_phishing'] else '🟢 LEGITIMATE'}")
            print(f"Confidence: {result['final_confidence']*100:.1f}%")
            
            if result['reasoning']:
                print("\nAnalysis Reasoning:")
                for reason in result['reasoning']:
                    print(f"  {reason}")
            
        except Exception as e:
            print(f"⚠️ Error during hybrid analysis: {e}")
    
    print("\n" + "="*70)
    print("Training complete! All visualizations have been generated.")
    print("="*70)
    print("\n✨ Features:")
    print("  • URL-based phishing detection (ML model)")
    print("  • Hybrid analysis (URL + Web Content)")
    print("  • Web content analysis (forms, links, keywords)")
    print("  • VirusTotal threat intelligence (optional)")
    print("  • Streamlit UI available: streamlit run app.py")
    print("="*70)
    print("\n📊 THREAT INTELLIGENCE SOURCES:")
    print("  ✓ URL analysis (15 features)")
    print("  ✓ Web content analysis (forms, links, keywords)")
    print("  ✓ VirusTotal API (external threat data)")
    print("    → Configure your API key in the Streamlit UI for best results")
    print("    → Get free API key at: https://www.virustotal.com/gui/my-apikey")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
