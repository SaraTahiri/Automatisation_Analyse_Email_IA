import os
import sys
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import json
import re
from pathlib import Path
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization

class EmailAnalyzer:
    """Analyseur d'emails avec vos modèles entraînés"""
    
    def __init__(self):
        self.models = {}
        self.scaler = None
        self.selected_features = None
        self._load_models()
    
    def _load_models(self):
        """Charger les modèles depuis votre entraînement"""
        try:
            # Chemin vers les modèles
            base_path = Path(__file__).parent.parent
            
            # Charger les modèles ML
            self.models['lr'] = joblib.load(base_path / 'models' / 'logistic_regression.pkl')
            self.models['rf'] = joblib.load(base_path / 'models' / 'random_forest.pkl')
            
            # Pour le modèle Deep Learning, nous allons recréer l'architecture
            # car il y a un problème de compatibilité avec le fichier .h5
            self.models['dl'] = self._create_dl_model()
            
            # Charger les poids pour le modèle DL (si disponibles)
            weights_path = base_path / 'models' / 'deep_learning_weights.h5'
            if weights_path.exists():
                self.models['dl'].load_weights(str(weights_path))
            
            # Charger le scaler et les features
            self.scaler = joblib.load(base_path / 'models' / 'scaler.pkl')
            self.selected_features = joblib.load(base_path / 'models' / 'selected_features.pkl')
            
            print("✅ Modèles chargés avec succès")
            
        except Exception as e:
            print(f"❌ Erreur chargement modèles: {e}")
            # Créer un modèle DL par défaut
            self.models['dl'] = self._create_default_dl_model()
    
    def _create_dl_model(self):
        """Recréer l'architecture du modèle DL basé sur votre code d'entraînement"""
        n_features = 3  # Selon vos features sélectionnées
        
        model = Sequential([
            Dense(128, activation='relu', input_dim=n_features),
            BatchNormalization(),
            Dropout(0.4),
            
            Dense(64, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            
            Dense(32, activation='relu'),
            Dropout(0.2),
            
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'AUC']
        )
        
        return model
    
    def _create_default_dl_model(self):
        """Créer un modèle DL par défaut si les poids ne sont pas disponibles"""
        return self._create_dl_model()
    
    def extract_features_from_text(self, text):
        """Extraire les features du texte d'email"""
        # Nettoyage du texte
        text = str(text).lower()
        
        # Calculer les métriques de base
        features = {
            'text_length': len(text),
            'word_count': len(text.split()),
            'suspicious_word_count': self._count_suspicious_words(text),
            'url_count': len(re.findall(r'https?://\S+', text)),
            'https_url_count': len(re.findall(r'https://\S+', text)),
            'unique_domains': self._count_unique_domains(text),
            'spf_present': 0,  # À implémenter avec vrai parser
            'dkim_present': 0,
            'dmarc_present': 0,
            'attachment_count': 0,
            'dangerous_attachment': 0
        }
        
        return features
    
    def _count_suspicious_words(self, text):
        """Compter les mots suspects"""
        suspicious_words = [
            'urgent', 'immediate', 'verify', 'account', 'password',
            'login', 'bank', 'paypal', 'security', 'update',
            'confirm', 'suspended', 'limited', 'click', 'link',
            'verify', 'secure', 'alert', 'warning', 'important',
            'action required', 'security check', 'phishing', 'fraud',
            'hack', 'compromised', 'credentials', 'authenticate'
        ]
        
        count = 0
        text_lower = text.lower()
        for word in suspicious_words:
            if word in text_lower:
                count += 1
        
        return count
    
    def _count_unique_domains(self, text):
        """Compter les domaines uniques dans les URLs"""
        urls = re.findall(r'https?://([^/\s]+)', text)
        domains = set()
        for url in urls:
            # Extraire le domaine principal
            domain = url.split('.')[-2] if '.' in url else url
            domains.add(domain)
        
        return len(domains)
    
    def analyze(self, email_text, model_type='ensemble'):
        """
        Analyser un email
        
        Args:
            email_text: Contenu de l'email
            model_type: 'lr', 'rf', 'dl', ou 'ensemble'
        
        Returns:
            Dict avec résultats de l'analyse
        """
        try:
            # Extraire les features
            features = self.extract_features_from_text(email_text)
            
            # Préparer les features pour la prédiction
            feature_values = {}
            for feature in self.selected_features:
                if feature in features:
                    feature_values[feature] = features[feature]
                else:
                    feature_values[feature] = 0  # Valeur par défaut
            
            # Convertir en DataFrame
            X = pd.DataFrame([feature_values])[self.selected_features]
            
            # Standardiser si le scaler est disponible
            if self.scaler is not None:
                X_scaled = self.scaler.transform(X)
            else:
                X_scaled = X.values
            
            # Prédictions
            predictions = {}
            
            # Logistic Regression
            if model_type in ['ensemble', 'lr'] and 'lr' in self.models:
                try:
                    predictions['lr'] = float(self.models['lr'].predict_proba(X_scaled)[0, 1])
                except:
                    predictions['lr'] = 0.5  # Valeur par défaut
            
            # Random Forest
            if model_type in ['ensemble', 'rf'] and 'rf' in self.models:
                try:
                    predictions['rf'] = float(self.models['rf'].predict_proba(X_scaled)[0, 1])
                except:
                    predictions['rf'] = 0.5
            
            # Deep Learning
            if model_type in ['ensemble', 'dl'] and 'dl' in self.models:
                try:
                    dl_pred = self.models['dl'].predict(X_scaled, verbose=0)
                    predictions['dl'] = float(dl_pred[0][0])
                except Exception as e:
                    print(f"Erreur prédiction DL: {e}")
                    predictions['dl'] = 0.5
            
            # Score final (moyenne pour ensemble)
            if model_type == 'ensemble' and predictions:
                scores = list(predictions.values())
                confidence = np.mean(scores)
            elif model_type in predictions:
                confidence = predictions[model_type]
            else:
                confidence = 0.5  # Valeur par défaut
            
            # Détection des risques
            risks = self._detect_risks(features)
            
            # Classification finale
            classification = self._classify_email(confidence, features, risks)
            
            return {
                'classification': classification,
                'confidence': float(confidence),
                'predictions': predictions,
                'features': features,
                'risks': risks,
                'model_used': model_type,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Erreur analyse: {e}")
            # Retourner un résultat par défaut en cas d'erreur
            return self._default_result()
    
    def _detect_risks(self, features):
        """Détecter les risques basés sur les features"""
        risks = []
        
        if features.get('suspicious_word_count', 0) > 3:
            risks.append({
                'type': 'SUSPICIOUS_KEYWORDS',
                'severity': 'HIGH',
                'description': f"{features['suspicious_word_count']} mots suspects détectés",
                'recommendation': 'Contenu potentiellement frauduleux'
            })
        
        url_count = features.get('url_count', 0)
        https_count = features.get('https_url_count', 0)
        
        if url_count > 5:
            risks.append({
                'type': 'MULTIPLE_URLS',
                'severity': 'MEDIUM',
                'description': f"{url_count} URLs détectées",
                'recommendation': 'Nombre élevé de liens suspects'
            })
        
        if url_count > 0 and https_count / url_count < 0.5:
            risks.append({
                'type': 'INSECURE_URLS',
                'severity': 'HIGH',
                'description': 'URLs non sécurisées (HTTP) détectées',
                'recommendation': 'Liens potentiellement malveillants'
            })
        
        if features.get('text_length', 0) < 50:
            risks.append({
                'type': 'SHORT_MESSAGE',
                'severity': 'LOW',
                'description': 'Message très court',
                'recommendation': 'Vérifier la légitimité'
            })
        
        return risks
    
    def _classify_email(self, confidence, features, risks):
        """Classifier l'email"""
        # Basé sur vos résultats d'entraînement
        if confidence >= 0.7:
            label = "PHISHING"
            level = "HIGH"
            color = "#dc3545"
            action = "BLOCK"
        elif confidence >= 0.4:
            label = "SUSPICIOUS"
            level = "MEDIUM"
            color = "#ffc107"
            action = "QUARANTINE"
        else:
            label = "LEGITIMATE"
            level = "LOW"
            color = "#28a745"
            action = "ALLOW"
        
        # Vérifier pour spam
        suspicious_words = features.get('suspicious_word_count', 0)
        if suspicious_words > 5 and features.get('url_count', 0) == 0:
            label = "SPAM"
            level = "MEDIUM"
            color = "#6c757d"
            action = "SPAM_FOLDER"
        
        return {
            'label': label,
            'level': level,
            'color': color,
            'action': action,
            'recommendation': self._get_recommendation(label, risks)
        }
    
    def _get_recommendation(self, label, risks):
        """Obtenir une recommandation basée sur la classification"""
        recommendations = {
            "PHISHING": "🚨 Email malveillant - Bloquer immédiatement",
            "SUSPICIOUS": "⚠️ Email suspect - Mettre en quarantaine pour vérification",
            "SPAM": "📧 Email spam - Mettre dans le dossier spam",
            "LEGITIMATE": "✅ Email légitime - Autoriser"
        }
        
        if risks:
            risk_count = len([r for r in risks if r['severity'] in ['HIGH', 'CRITICAL']])
            if risk_count > 0 and label == "LEGITIMATE":
                return "⚠️ Email légitime mais avec risques - Vérification recommandée"
        
        return recommendations.get(label, "📧 Email à analyser manuellement")
    
    def _default_result(self):
        """Résultat par défaut en cas d'erreur"""
        return {
            'classification': {
                'label': 'ERROR',
                'level': 'UNKNOWN',
                'color': '#6c757d',
                'action': 'REVIEW',
                'recommendation': 'Erreur lors de l\'analyse'
            },
            'confidence': 0.5,
            'predictions': {},
            'features': {},
            'risks': [],
            'model_used': 'error',
            'timestamp': datetime.now().isoformat()
        }

# Test de l'analyseur
if __name__ == "__main__":
    print("🧪 Test de l'analyseur...")
    analyzer = EmailAnalyzer()
    
    # Test avec un exemple d'email
    test_email = """From: security@bank-support.com
    To: user@example.com
    Subject: URGENT: Account Verification Required
    
    Dear Customer,
    
    We have detected unusual activity on your account.
    Please verify your identity immediately by clicking:
    http://fake-bank-verify.com/login
    
    Regards,
    Security Team"""
    
    result = analyzer.analyze(test_email)
    print(f"Résultat: {result['classification']['label']}")
    print(f"Confiance: {result['confidence']:.1%}")
    print(f"Risques détectés: {len(result['risks'])}")