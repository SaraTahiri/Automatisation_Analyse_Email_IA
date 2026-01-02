"streamlit run app.py"
import os
import sys
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
import time
from utils.email_analyzer import EmailAnalyzer

# Ajouter le chemin parent pour les imports
sys.path.append(str(Path(__file__).parent))

# Titre de l'application
st.set_page_config(
    page_title="Phishing Detection AI",
    page_icon="🛡️",
    layout="wide"
)

# CSS personnalisé
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 1rem;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
    }
    .metric-label {
        font-size: 0.9rem;
        opacity: 0.9;
    }
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #28a745 0%, #ffc107 50%, #dc3545 100%);
    }
    .risk-high {
        color: #dc3545;
        font-weight: bold;
    }
    .risk-medium {
        color: #ffc107;
        font-weight: bold;
    }
    .risk-low {
        color: #28a745;
        font-weight: bold;
    }
    .nav-button {
        width: 100%;
        margin-bottom: 10px;
        text-align: left;
        padding: 10px 15px;
    }
</style>
""", unsafe_allow_html=True)

class PhishingDetectionApp:
    def __init__(self):
        self.analyzer = EmailAnalyzer()
        
    def analyze_text(self, email_text, model_type='rf'):
        """Analyser un texte d'email avec vos vrais modèles"""
        try:
            if not email_text.strip():
                return None
            
            # Utiliser l'analyseur avec vos modèles
            result = self.analyzer.analyze(email_text, model_type)
            
            # Formater pour l'affichage
            formatted_result = {
                'classification': result['classification']['label'],
                'confidence': result['confidence'],
                'risk_level': result['classification']['level'],
                'color': result['classification']['color'],
                'predictions': result['predictions'],
                'features': result['features'],
                'risks': result['risks'],
                'recommendation': result['classification']['recommendation'],
                'action': result['classification']['action']
            }
            
            return formatted_result
            
        except Exception as e:
            st.error(f"Erreur d'analyse: {e}")
            return None  

def main():
    app = PhishingDetectionApp()
    
    # Header principal
    st.markdown("<h1 class='main-header'>🛡️ Phishing Detection AI System</h1>", 
                unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.title("⚙️ Configuration")
        
        # Sélection du modèle
        model_choice = st.selectbox(
            "Modèle de détection",
            ["Random Forest", "Logistic Regression", "Ensemble"]
        )
        
        # Seuil de confiance
        threshold = st.slider(
            "Seuil de détection",
            min_value=0.1,
            max_value=1.0,
            value=0.5,
            step=0.1
        )
        
        st.divider()
        
        # Statistiques
        st.title("📊 Statistiques")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Emails analysés", "15709")
        with col2:
            st.metric("Taux phishing", "37.1%")
        
        st.divider()
        
        # Navigation avec boutons (pour versions Streamlit < 1.26.0)
        st.title("🔗 Navigation")
        
        nav_pages = {
            "🏠 Accueil": "app.py",
            "📤 Upload Email": "pages/upload.py",
            "🔍 Analyse en direct": "pages/analyze.py",
            "📊 Historique": "pages/history.py",
            "📈 Statistiques": "pages/statistics.py"
        }
        
        for label, page in nav_pages.items():
            if st.button(label, key=f"nav_{label}", use_container_width=True):
                st.switch_page(page)
        
        st.divider()
        
        # Aide et support
        st.title("❓ Aide")
        st.info("Pour plus d'aide : saratahiri73@gmail.com")
    
    # Contenu principal
    tab1, tab2, tab3, tab4 = st.tabs([
        "🏠 Accueil", 
        "📤 Upload Email", 
        "🔍 Analyse directe",
        "📊 Dashboard"
    ])
    
    with tab1:
        # Section 1: Introduction
        st.header("🎯 Bienvenue dans le système de détection de phishing")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-value">99%</div>
                <div class="metric-label">Précision</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-value">&lt;1s</div>
                <div class="metric-label">Temps d'analyse</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="metric-card">
                <div class="metric-value">3</div>
                <div class="metric-label">Modèles IA</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Section 2: Dernières détections
        st.header("🚨 Dernières alertes")
        
        # Données de démo
        recent_alerts = [
            {"email": "urgent@bank-secure.com", "risk": "HIGH", "time": "2 min"},
            {"email": "update@paypal-verify.net", "risk": "HIGH", "time": "15 min"},
            {"email": "newsletter@company.com", "risk": "LOW", "time": "1h"},
            {"email": "security@microsoft-update.com", "risk": "MEDIUM", "time": "2h"}
        ]
        
        for alert in recent_alerts:
            risk_color = {
                "HIGH": "🔴",
                "MEDIUM": "🟡", 
                "LOW": "🟢"
            }.get(alert["risk"], "⚪")
            
            with st.expander(f"{risk_color} {alert['email']} - {alert['time']}"):
                st.write(f"**Niveau de risque:** {alert['risk']}")
                st.write("**Action recommandée:**")
                if alert["risk"] == "HIGH":
                    st.error("🚨 Bloquer immédiatement")
                elif alert["risk"] == "MEDIUM":
                    st.warning("⚠️ Mettre en quarantaine")
                else:
                    st.success("✅ Email sécurisé")
        
        # Section 3: Statistiques rapides
        st.header("📈 Vue d'ensemble")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Graphique des types d'emails
            fig = go.Figure(data=[
                go.Pie(
                    labels=['Légitimes', 'Phishing', 'Spam', 'Malware'],
                    values=[62.9, 37.1, 5.2, 1.8],
                    hole=0.3
                )
            ])
            fig.update_layout(title="Distribution des emails")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Graphique de tendance
            dates = pd.date_range(end=datetime.now(), periods=7, freq='D')
            phishing_counts = [12, 8, 15, 10, 7, 9, 11]
            
            fig2 = go.Figure(data=[
                go.Scatter(
                    x=dates,
                    y=phishing_counts,
                    mode='lines+markers',
                    name='Phishing détectés',
                    line=dict(color='red', width=3)
                )
            ])
            fig2.update_layout(
                title="Tendance quotidienne",
                xaxis_title="Date",
                yaxis_title="Nombre de phishing"
            )
            st.plotly_chart(fig2, use_container_width=True)
            
        # Section 4: Comment utiliser
        st.header("🎮 Comment utiliser")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.info("""
            **📤 Upload Email**
            1. Cliquez sur Upload Email
            2. Sélectionnez votre fichier .eml
            3. Lancez l'analyse
            """)
        
        with col2:
            st.info("""
            **🔍 Analyse directe**
            1. Collez le contenu de l'email
            2. Spécifiez l'expéditeur
            3. Obtenez l'analyse en temps réel
            """)
        
        with col3:
            st.info("""
            **📊 Visualisation**
            1. Consultez l'historique
            2. Analysez les tendances
            3. Exportez les rapports
            """)
    
    with tab2:
        st.header("📤 Uploader un email")
        
        uploaded_file = st.file_uploader(
            "Choisissez un fichier .eml",
            type=['eml', 'txt'],
            help="Format supporté: .eml, .txt"
        )
        
        if uploaded_file is not None:
            # Lire le contenu
            email_content = uploaded_file.getvalue().decode('utf-8')
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.subheader("📄 Contenu de l'email")
                st.text_area("", email_content, height=300, disabled=True)
            
            with col2:
                st.subheader("📊 Métadonnées")
                st.write(f"**Nom:** {uploaded_file.name}")
                st.write(f"**Taille:** {uploaded_file.size / 1024:.1f} KB")
                
                # Bouton d'analyse
                if st.button("🔍 Analyser cet email", type="primary", use_container_width=True):
                    with st.spinner("Analyse en cours..."):
                        result = app.analyze_text(email_content)
                        
                        if result:
                            st.divider()
                            st.subheader("🎯 Résultat de l'analyse")
                            
                            # Afficher le score de confiance
                            st.metric(
                                "Score de confiance", 
                                f"{result['confidence']:.1%}",
                                delta_color="inverse"
                            )
                            
                            # Barre de progression colorée
                            st.progress(result['confidence'])
                            
                            # Classification avec couleur
                            st.markdown(
                                f"<h3 style='color:{result['color']}'>{result['classification']}</h3>",
                                unsafe_allow_html=True
                            )
                            
                            # Détails des prédictions
                            with st.expander("🔍 Détails des modèles"):
                                for model_name, score in result['predictions'].items():
                                    st.write(f"**{model_name}:** {score:.1%}")
            
            # Section pour coller du texte
            st.divider()
            st.subheader("📝 Ou coller directement le contenu")
            
            pasted_text = st.text_area(
                "Collez le contenu de l'email ici:",
                height=200,
                placeholder="De: support@bank.com\nÀ: client@email.com\n\nCher client, votre compte a été suspendu..."
            )
            
            if st.button("🔍 Analyser le texte", use_container_width=True):
                if pasted_text:
                    with st.spinner("Analyse en cours..."):
                        result = app.analyze_text(pasted_text)
                        
                        if result:
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.metric("Confiance", f"{result['confidence']:.1%}")
                                st.progress(result['confidence'])
                            
                            with col2:
                                risk_class = f"risk-{result['risk_level'].lower()}"
                                st.markdown(
                                    f"<h3 class='{risk_class}'>{result['classification']}</h3>",
                                    unsafe_allow_html=True
                                )
    
    with tab3:
        st.header("🔍 Analyse en temps réel")
        
        # Mode rapide
        st.subheader("🚀 Analyse rapide")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            urls = st.text_input("URLs suspectes", placeholder="http://example.com")
        
        with col2:
            subject = st.text_input("Sujet", placeholder="URGENT: Vérification de compte")
        
        with col3:
            sender = st.text_input("Expéditeur", placeholder="noreply@bank-security.com")
        
        # Zone de texte pour le corps
        email_body = st.text_area(
            "Corps de l'email",
            height=200,
            placeholder="Cher client,\n\nVotre compte a été bloqué pour des raisons de sécurité..."
        )
        
        # Bouton d'analyse
        if st.button("🚀 Lancer l'analyse", type="primary", use_container_width=True):
            # Combiner les champs pour l'analyse
            full_text = f"Sujet: {subject}\n\nDe: {sender}\n\n{email_body}\n\nURLs: {urls}"
            
            with st.spinner("🧠 L'IA analyse l'email..."):
                result = app.analyze_text(full_text)
                
                if result:
                    # Afficher les résultats
                    st.divider()
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        # Jauge de risque
                        fig = go.Figure(go.Indicator(
                            mode = "gauge+number",
                            value = result['confidence'] * 100,
                            title = {'text': "Niveau de risque"},
                            gauge = {
                                'axis': {'range': [0, 100]},
                                'bar': {'color': result['color']},
                                'steps': [
                                    {'range': [0, 40], 'color': "lightgreen"},
                                    {'range': [40, 70], 'color': "yellow"},
                                    {'range': [70, 100], 'color': "red"}
                                ]
                            }
                        ))
                        fig.update_layout(height=300)
                        st.plotly_chart(fig, use_container_width=True)
                    
                    with col2:
                        st.subheader("📋 Risques détectés")
                        
                        # Liste des risques basés sur les features
                        risks = []
                        features = result['features']
                        
                        if features.get('suspicious_word_count', 0) > 2:
                            risks.append(("🔴", "Mots suspects", "HIGH"))
                        
                        if features.get('url_count', 0) > 0 and features.get('https_url_count', 0) == 0:
                            risks.append(("🟠", "URLs non sécurisées", "MEDIUM"))
                        
                        if features.get('url_count', 0) > 5:
                            risks.append(("🟡", "Trop d'URLs", "MEDIUM"))
                        
                        if not risks:
                            st.success("✅ Aucun risque majeur détecté")
                        else:
                            for icon, risk, level in risks:
                                st.write(f"{icon} **{risk}** - *{level}*")
                        
                        # Recommandation
                        st.divider()
                        st.subheader("💡 Recommandation")
                        if result['risk_level'] == "HIGH":
                            st.error("🚨 **BLOQUER** - Email très suspect")
                        elif result['risk_level'] == "MEDIUM":
                            st.warning("⚠️ **QUARANTAINE** - Nécessite vérification")
                        else:
                            st.success("✅ **AUTORISER** - Email probablement légitime")
    
    with tab4:
        st.header("📊 Dashboard statistique")
        
        # Données de démo pour les graphiques
        days = ['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim']
        legitimate = [120, 135, 110, 145, 130, 95, 105]
        phishing = [45, 38, 52, 41, 39, 28, 35]
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Graphique à barres
            fig = go.Figure(data=[
                go.Bar(name='Légitimes', x=days, y=legitimate, marker_color='green'),
                go.Bar(name='Phishing', x=days, y=phishing, marker_color='red')
            ])
            fig.update_layout(
                title="Détections par jour",
                barmode='group',
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Graphique de performance des modèles
            models = ['Random Forest', 'Logistic', 'Deep Learning']
            accuracy = [0.85, 0.78, 0.82]
            
            fig2 = go.Figure(data=[
                go.Bar(x=models, y=accuracy, marker_color=['#FF6B6B', '#4ECDC4', '#45B7D1'])
            ])
            fig2.update_layout(
                title="Précision des modèles",
                yaxis=dict(range=[0, 1]),
                height=400
            )
            st.plotly_chart(fig2, use_container_width=True)
        
        # Métriques détaillées
        st.subheader("📈 Métriques détaillées")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Taux de phishing", "37.1%", "2.3%")
        
        with col2:
            st.metric("Précision RF", "85.2%", "1.1%")
        
        with col3:
            st.metric("Faux positifs", "4.3%", "-0.5%")
        
        with col4:
            st.metric("Temps moyen", "0.8s", "-0.2s")
        
        # Top domaines suspects
        st.subheader("🌐 Top domaines suspects")
        
        suspicious_domains = {
            'secure-bank-update.com': 42,
            'paypal-verification.net': 38,
            'microsoft-security.xyz': 31,
            'amazon-payment-verify.com': 28,
            'google-account-recovery.io': 25
        }
        
        for domain, count in suspicious_domains.items():
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"`{domain}`")
            with col2:
                st.write(f"**{count}** emails")

if __name__ == "__main__":
    main()