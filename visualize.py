"""
Visualization utilities for displaying model performance and insights.
Generates and saves graphs for accuracy, confusion matrix, and feature importance.
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.metrics import confusion_matrix


def plot_accuracy(accuracy, save_path='accuracy.png'):
    """
    Create and save an accuracy visualization.
    
    Args:
        accuracy (float): Accuracy score (0-1)
        save_path (str): Path to save the image
    """
    fig, ax = plt.subplots(figsize=(10, 6))
    
    categories = ['Accuracy', 'Error Rate']
    values = [accuracy * 100, (1 - accuracy) * 100]
    colors = ['#2ecc71', '#e74c3c']
    
    bars = ax.bar(categories, values, color=colors, edgecolor='black', linewidth=2)
    
    # Add value labels on bars
    for bar, value in zip(bars, values):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{value:.2f}%', ha='center', va='bottom', fontsize=12, fontweight='bold')
    
    ax.set_ylabel('Percentage (%)', fontsize=12, fontweight='bold')
    ax.set_title('Model Accuracy', fontsize=14, fontweight='bold', pad=20)
    ax.set_ylim(0, 110)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"Accuracy graph saved to {save_path}")
    plt.close()


def plot_confusion_matrix(y_true, y_pred, save_path='confusion_matrix.png'):
    """
    Create and save a confusion matrix visualization.
    
    Args:
        y_true (array): True labels
        y_pred (array): Predicted labels
        save_path (str): Path to save the image
    """
    cm = confusion_matrix(y_true, y_pred)
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=True, ax=ax,
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'],
                cbar_kws={'label': 'Count'})
    
    ax.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
    ax.set_ylabel('True Label', fontsize=12, fontweight='bold')
    ax.set_title('Confusion Matrix', fontsize=14, fontweight='bold', pad=20)
    
    # Add text annotations
    plt.figtext(0.5, 0.02, f'TN: {cm[0][0]} | FP: {cm[0][1]} | FN: {cm[1][0]} | TP: {cm[1][1]}',
                ha='center', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"Confusion matrix saved to {save_path}")
    plt.close()


def plot_feature_importance(feature_importance_dict, save_path='feature_importance.png'):
    """
    Create and save a feature importance visualization.
    
    Args:
        feature_importance_dict (dict): Dictionary of feature names and their importance scores
        save_path (str): Path to save the image
    """
    # Sort features by importance
    sorted_features = sorted(feature_importance_dict.items(), key=lambda x: x[1], reverse=True)
    features, importances = zip(*sorted_features[:10])  # Top 10 features
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    colors = plt.cm.RdYlGn(np.linspace(0.3, 0.9, len(features)))
    bars = ax.barh(features, importances, color=colors, edgecolor='black', linewidth=1.5)
    
    # Add value labels
    for bar, importance in zip(bars, importances):
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height()/2.,
                f'{importance:.4f}', ha='left', va='center', fontsize=10, fontweight='bold')
    
    ax.set_xlabel('Importance Score', fontsize=12, fontweight='bold')
    ax.set_title('Top 10 Most Important Features', fontsize=14, fontweight='bold', pad=20)
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"Feature importance graph saved to {save_path}")
    plt.close()


def plot_metrics(metrics_dict, save_path='metrics.png'):
    """
    Create and save a metrics comparison visualization.
    
    Args:
        metrics_dict (dict): Dictionary containing accuracy, precision, recall, f1_score
        save_path (str): Path to save the image
    """
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
    values = [metrics_dict['accuracy'], metrics_dict['precision'], 
              metrics_dict['recall'], metrics_dict['f1_score']]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
    bars = ax.bar(metrics, values, color=colors, edgecolor='black', linewidth=2)
    
    # Add value labels
    for bar, value in zip(bars, values):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{value:.4f}', ha='center', va='bottom', fontsize=11, fontweight='bold')
    
    ax.set_ylabel('Score', fontsize=12, fontweight='bold')
    ax.set_title('Model Performance Metrics', fontsize=14, fontweight='bold', pad=20)
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"Metrics graph saved to {save_path}")
    plt.close()
