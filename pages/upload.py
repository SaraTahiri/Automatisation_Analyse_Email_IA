import streamlit as st
import pandas as pd
from datetime import datetime
import base64
import sys
from pathlib import Path

# Ajouter le chemin pour les imports
sys.path.append(str(Path(__file__).parent.parent))
from utils.email_analyzer import EmailAnalyzer

st.set_page_config(page_title="Upload Email", page_icon="📤")

# Initialiser l'analyseur
@st.cache_resource
def get_analyzer():
    return EmailAnalyzer()

analyzer = get_analyzer()

st.title("📤 Upload Email")

st.markdown("""
### Téléchargez vos fichiers email pour analyse

Le système utilisera vos modèles entraînés :
- **Logistic Regression** (AUC: 0.615)
- **Random Forest** (AUC: 0.678)
- **Deep Learning** (AUC: 0.638)
""")

# Sélection du modèle
model_type = st.selectbox(
    "Choisissez le modèle d'analyse",
    ["ensemble", "rf", "lr", "dl"],
    help="ensemble = moyenne des 3 modèles"
)

# Section upload
uploaded_file = st.file_uploader(
    "Choisissez un fichier",
    type=['eml', 'txt'],
    help="Maximum 10MB"
)

if uploaded_file is not None:
    # Lire le contenu
    content = uploaded_file.getvalue().decode('utf-8', errors='ignore')
    
    # Afficher les informations du fichier
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Nom", uploaded_file.name)
    
    with col2:
        st.metric("Taille", f"{uploaded_file.size / 1024:.1f} KB")
    
    with col3:
        # Analyser rapidement pour prévisualiser
        with st.spinner("Analyse rapide..."):
            preview_result = analyzer.analyze(content[:1000], model_type)
            risk_color = {
                "HIGH": "🔴",
                "MEDIUM": "🟡", 
                "LOW": "🟢"
            }.get(preview_result['classification']['level'], "⚪")
            st.metric("Risque initial", risk_color)
    
    # Aperçu du contenu
    st.subheader("📄 Aperçu")
    
    with st.expander("Voir le contenu"):
        st.text(content[:2000] + ("..." if len(content) > 2000 else ""))
    
    # Boutons d'action
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔍 Analyser complètement", type="primary", use_container_width=True):
            # Stocker pour l'analyse complète
            st.session_state['email_content'] = content
            st.session_state['model_type'] = model_type
            st.session_state['filename'] = uploaded_file.name
            st.switch_page("pages/analyze.py")
    
    with col2:
        st.download_button(
            label="💾 Télécharger",
            data=content,
            file_name=uploaded_file.name,
            mime="text/plain"
        )

# Section pour coller du texte
st.divider()
st.subheader("📝 Ou coller directement le contenu")

pasted_text = st.text_area(
    "Collez le contenu de l'email ici:",
    height=200,
    placeholder="De: security@bank.com\nÀ: client@email.com\n\nCher client, votre compte a été suspendu..."
)

if pasted_text and st.button("🔍 Analyser le texte collé", use_container_width=True):
    st.session_state['email_content'] = pasted_text
    st.session_state['model_type'] = model_type
    st.session_state['filename'] = "texte_collé.txt"
    st.switch_page("pages/analyze.py")

# Section exemple avec vrai email de phishing
st.divider()
st.subheader("🎯 Exemple d'email phishing")

example_email = """From: security@bank-support.com
To: user@example.com
Subject: URGENT: Your Account Has Been Suspended

Dear Valued Customer,

We have detected unusual activity on your bank account. 
For your security, we have temporarily suspended your account.

To restore access, please verify your identity by clicking:
http://bank-verify-security.com/login

Important: You must complete this verification within 24 hours 
or your account will be permanently closed.

This is an automated message. Please do not reply.

Bank Security Team"""

if st.button("🚀 Tester avec cet exemple", type="secondary"):
    st.session_state['email_content'] = example_email
    st.session_state['model_type'] = model_type
    st.session_state['filename'] = "exemple_phishing.eml"
    st.switch_page("pages/analyze.py")