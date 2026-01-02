"""
Agent IA Intelligent pour l'analyse d'emails
Phase 4 - PFA : Automatisation de l'analyse de sécurité des emails
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Tuple
import json

# Imports des modules du projet
sys.path.append(os.path.abspath(".."))
from extraction.email_parser import parse_email
from preprocessing.text_preprocessing import clean_text
from features.feature_extraction import extract_all_features


class EmailSecurityAgent:
    """
    Agent IA intelligent pour l'analyse de sécurité des emails
    """
    
    def __init__(self, models_dir: str = "../models"):
        """
        Initialisation de l'agent
        
        Args:
            models_dir: Répertoire contenant les modèles entraînés
        """
        self.models_dir = models_dir
        self.models = {}
        self.scaler = None
        self.selected_features = None
        
        # Chargement des modèles
        self._load_models()
        
        # Historique des analyses
        self.history_file = "../data/analysis_history.json"
        self.history = self._load_history()
    
    def _load_models(self):
        """Chargement des modèles ML/DL"""
        try:
            print("🔄 Chargement des modèles...")
            
            # Logistic Regression
            self.models['lr'] = joblib.load(
                os.path.join(self.models_dir, 'logistic_regression.pkl')
            )
            
            # Random Forest
            self.models['rf'] = joblib.load(
                os.path.join(self.models_dir, 'random_forest.pkl')
            )
            
            # Deep Learning
            from tensorflow.keras.models import load_model
            self.models['dl'] = load_model(
                os.path.join(self.models_dir, 'deep_learning.h5')
            )
            
            # Scaler et features
            self.scaler = joblib.load(
                os.path.join(self.models_dir, 'scaler.pkl')
            )
            self.selected_features = joblib.load(
                os.path.join(self.models_dir, 'selected_features.pkl')
            )
            
            print("✅ Modèles chargés avec succès")
            
        except Exception as e:
            print(f"❌ Erreur lors du chargement des modèles : {e}")
            raise
    
    def _load_history(self) -> List[Dict]:
        """Chargement de l'historique des analyses"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def _save_history(self):
        """Sauvegarde de l'historique"""
        os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
        with open(self.history_file, 'w') as f:
            json.dump(self.history, f, indent=2, default=str)
    
    def analyze_email(self, email_path: str, model_type: str = 'rf') -> Dict:
        """
        Analyse complète d'un email
        
        Args:
            email_path: Chemin vers le fichier .eml
            model_type: Type de modèle ('lr', 'rf', 'dl', 'ensemble')
        
        Returns:
            Dictionnaire avec les résultats de l'analyse
        """
        try:
            # 1. Extraction des données
            email_data = parse_email(email_path)
            
            # 2. Prétraitement
            clean_body = clean_text(email_data['Body_Text'])
            
            # 3. Extraction des features
            features = extract_all_features(email_data, clean_body)
            
            # 4. Préparation pour la prédiction
            X = pd.DataFrame([features])[self.selected_features]
            X_scaled = self.scaler.transform(X)
            
            # 5. Prédiction
            if model_type == 'ensemble':
                prediction, confidence = self._ensemble_predict(X_scaled)
            else:
                prediction, confidence = self._single_model_predict(
                    X_scaled, model_type
                )
            
            # 6. Détection des risques
            risks = self._detect_risks(email_data, features, clean_body)
            
            # 7. Classification
            classification = self._classify_threat(prediction, confidence, risks)
            
            # 8. Génération du rapport
            result = {
                'timestamp': datetime.now(),
                'email_path': email_path,
                'email_data': {
                    'from': email_data['From'],
                    'to': email_data['To'],
                    'subject': email_data['Subject'],
                    'date': email_data['Date']
                },
                'prediction': prediction,
                'confidence': float(confidence),
                'classification': classification,
                'risks': risks,
                'features': features,
                'model_used': model_type
            }
            
            # 9. Ajout à l'historique
            self.history.append(result)
            self._save_history()
            
            return result
            
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse : {e}")
            raise
    
    def _single_model_predict(self, X_scaled: np.ndarray, 
                             model_type: str) -> Tuple[int, float]:
        """Prédiction avec un seul modèle"""
        model = self.models[model_type]
        
        if model_type == 'dl':
            proba = model.predict(X_scaled, verbose=0).flatten()[0]
        else:
            proba = model.predict_proba(X_scaled)[0, 1]
        
        prediction = int(proba > 0.5)
        return prediction, proba
    
    def _ensemble_predict(self, X_scaled: np.ndarray) -> Tuple[int, float]:
        """Prédiction par ensemble (moyenne pondérée)"""
        # Poids pour chaque modèle (à ajuster selon performances)
        weights = {
            'lr': 0.2,
            'rf': 0.5,
            'dl': 0.3
        }
        
        probas = []
        for model_type, weight in weights.items():
            _, proba = self._single_model_predict(X_scaled, model_type)
            probas.append(proba * weight)
        
        final_proba = sum(probas)
        prediction = int(final_proba > 0.5)
        
        return prediction, final_proba
    
    def _detect_risks(self, email_data: Dict, features: Dict, 
                     clean_text: str) -> List[Dict]:
        """
        Détection détaillée des risques
        
        Returns:
            Liste des risques détectés avec niveau de sévérité
        """
        risks = []
        
        # 1. Vérification des protocoles de sécurité
        if not features.get('spf_present'):
            risks.append({
                'type': 'SPF_MISSING',
                'severity': 'HIGH',
                'description': 'Aucune vérification SPF détectée',
                'recommendation': 'Email peut être usurpé'
            })
        
        if not features.get('dkim_present'):
            risks.append({
                'type': 'DKIM_MISSING',
                'severity': 'HIGH',
                'description': 'Aucune signature DKIM détectée',
                'recommendation': 'Authenticité du domaine non vérifiée'
            })
        
        if not features.get('dmarc_present'):
            risks.append({
                'type': 'DMARC_MISSING',
                'severity': 'MEDIUM',
                'description': 'Aucune politique DMARC détectée',
                'recommendation': 'Politique d\'authentification absente'
            })
        
        # 2. Vérification des mots suspects
        if features.get('suspicious_word_count', 0) > 0:
            risks.append({
                'type': 'SUSPICIOUS_KEYWORDS',
                'severity': 'MEDIUM',
                'description': f"{features['suspicious_word_count']} mots suspects détectés",
                'recommendation': 'Contenu potentiellement frauduleux'
            })
        
        # 3. Vérification des URLs
        if features.get('url_count', 0) > 5:
            risks.append({
                'type': 'MULTIPLE_URLS',
                'severity': 'MEDIUM',
                'description': f"{features['url_count']} URLs détectées",
                'recommendation': 'Nombre élevé de liens suspects'
            })
        
        https_ratio = (features.get('https_url_count', 0) / 
                      max(features.get('url_count', 1), 1))
        if features.get('url_count', 0) > 0 and https_ratio < 0.5:
            risks.append({
                'type': 'INSECURE_URLS',
                'severity': 'HIGH',
                'description': 'URLs non sécurisées (HTTP)',
                'recommendation': 'Liens potentiellement malveillants'
            })
        
        # 4. Vérification des attachments
        if features.get('dangerous_attachment', 0):
            risks.append({
                'type': 'DANGEROUS_ATTACHMENT',
                'severity': 'CRITICAL',
                'description': 'Pièce jointe potentiellement dangereuse',
                'recommendation': 'NE PAS ouvrir la pièce jointe'
            })
        
        # 5. Incohérence From/Reply-To
        email_from = email_data.get('From', '')
        reply_to = email_data.get('Reply-To', '')
        if reply_to and reply_to != email_from:
            risks.append({
                'type': 'FROM_REPLY_MISMATCH',
                'severity': 'HIGH',
                'description': 'Incohérence entre From et Reply-To',
                'recommendation': 'Possible tentative d\'usurpation'
            })
        
        return risks
    
    def _classify_threat(self, prediction: int, confidence: float, 
                        risks: List[Dict]) -> Dict:
        """
        Classification du niveau de menace
        
        Returns:
            Dictionnaire avec classification et recommandation
        """
        if prediction == 0:  # Légitime
            if confidence > 0.8:
                return {
                    'label': 'LEGITIMATE',
                    'level': 'SAFE',
                    'color': 'green',
                    'recommendation': 'Email sûr',
                    'action': 'ALLOW'
                }
            else:
                return {
                    'label': 'SUSPICIOUS',
                    'level': 'LOW',
                    'color': 'yellow',
                    'recommendation': 'Vérification manuelle recommandée',
                    'action': 'FLAG'
                }
        
        else:  # Malveillant
            # Déterminer le type de menace
            has_attachment = any(r['type'] == 'DANGEROUS_ATTACHMENT' for r in risks)
            has_urls = any(r['type'] in ['MULTIPLE_URLS', 'INSECURE_URLS'] for r in risks)
            
            if has_attachment:
                threat_type = 'MALWARE'
            elif has_urls:
                threat_type = 'PHISHING'
            else:
                threat_type = 'SPAM'
            
            if confidence > 0.9:
                level = 'CRITICAL'
                color = 'red'
                action = 'BLOCK'
            elif confidence > 0.7:
                level = 'HIGH'
                color = 'orange'
                action = 'QUARANTINE'
            else:
                level = 'MEDIUM'
                color = 'yellow'
                action = 'FLAG'
            
            return {
                'label': threat_type,
                'level': level,
                'color': color,
                'recommendation': f'Menace détectée : {threat_type}',
                'action': action
            }
    
    def get_statistics(self) -> Dict:
        """Génération des statistiques d'utilisation"""
        if not self.history:
            return {
                'total_analyzed': 0,
                'phishing_detected': 0,
                'legitimate': 0,
                'detection_rate': 0.0
            }
        
        df = pd.DataFrame(self.history)
        
        total = len(df)
        phishing = len(df[df['prediction'] == 1])
        legitimate = len(df[df['prediction'] == 0])
        
        # Top domaines attaquants
        phishing_df = df[df['prediction'] == 1]
        if len(phishing_df) > 0:
            from_addresses = phishing_df['email_data'].apply(
                lambda x: x.get('from', 'Unknown')
            )
            top_domains = from_addresses.value_counts().head(10).to_dict()
        else:
            top_domains = {}
        
        # Tendances temporelles
        df['date'] = pd.to_datetime(df['timestamp'])
        df['date_only'] = df['date'].dt.date
        daily_stats = df.groupby('date_only').agg({
            'prediction': ['count', 'sum']
        }).reset_index()
        
        return {
            'total_analyzed': total,
            'phishing_detected': phishing,
            'legitimate': legitimate,
            'detection_rate': (phishing / total * 100) if total > 0 else 0,
            'top_domains': top_domains,
            'daily_stats': daily_stats.to_dict('records'),
            'avg_confidence': float(df['confidence'].mean()),
            'classification_breakdown': df['classification'].apply(
                lambda x: x['label']
            ).value_counts().to_dict()
        }
    
    def generate_report(self, result: Dict) -> str:
        """
        Génération d'un rapport détaillé en format texte
        
        Args:
            result: Résultat de l'analyse
        
        Returns:
            Rapport formaté en texte
        """
        report = []
        report.append("=" * 80)
        report.append("RAPPORT D'ANALYSE DE SÉCURITÉ EMAIL")
        report.append("=" * 80)
        report.append("")
        
        # Informations générales
        report.append("📧 INFORMATIONS EMAIL")
        report.append("-" * 80)
        report.append(f"De      : {result['email_data']['from']}")
        report.append(f"À       : {result['email_data']['to']}")
        report.append(f"Sujet   : {result['email_data']['subject']}")
        report.append(f"Date    : {result['email_data']['date']}")
        report.append(f"Analysé : {result['timestamp']}")
        report.append("")
        
        # Classification
        classification = result['classification']
        report.append("🎯 CLASSIFICATION")
        report.append("-" * 80)
        report.append(f"Type        : {classification['label']}")
        report.append(f"Niveau      : {classification['level']}")
        report.append(f"Confiance   : {result['confidence']:.2%}")
        report.append(f"Recommandé  : {classification['recommendation']}")
        report.append(f"Action      : {classification['action']}")
        report.append("")
        
        # Risques détectés
        risks = result['risks']
        report.append(f"⚠️  RISQUES DÉTECTÉS ({len(risks)})")
        report.append("-" * 80)
        if risks:
            for i, risk in enumerate(risks, 1):
                report.append(f"{i}. [{risk['severity']}] {risk['type']}")
                report.append(f"   {risk['description']}")
                report.append(f"   → {risk['recommendation']}")
                report.append("")
        else:
            report.append("Aucun risque spécifique détecté")
            report.append("")
        
        # Features techniques
        report.append("🔍 ANALYSE TECHNIQUE")
        report.append("-" * 80)
        features = result['features']
        report.append(f"Longueur texte       : {features.get('text_length', 0)} caractères")
        report.append(f"Nombre de mots       : {features.get('word_count', 0)}")
        report.append(f"Mots suspects        : {features.get('suspicious_word_count', 0)}")
        report.append(f"URLs détectées       : {features.get('url_count', 0)}")
        report.append(f"URLs HTTPS           : {features.get('https_url_count', 0)}")
        report.append(f"SPF présent          : {'✓' if features.get('spf_present') else '✗'}")
        report.append(f"DKIM présent         : {'✓' if features.get('dkim_present') else '✗'}")
        report.append(f"DMARC présent        : {'✓' if features.get('dmarc_present') else '✗'}")
        report.append(f"Pièces jointes       : {features.get('attachment_count', 0)}")
        report.append("")
        
        report.append("=" * 80)
        report.append(f"Rapport généré par Agent IA - Modèle: {result['model_used']}")
        report.append("=" * 80)
        
        return "\n".join(report)


# Test de l'agent si exécuté directement
if __name__ == "__main__":
    print("🤖 Initialisation de l'Agent IA...")
    agent = EmailSecurityAgent()
    
    print("\n📊 Statistiques actuelles :")
    stats = agent.get_statistics()
    print(f"Total analysé : {stats['total_analyzed']}")
    print(f"Phishing détecté : {stats['phishing_detected']}")
    print(f"Taux de détection : {stats['detection_rate']:.2f}%")