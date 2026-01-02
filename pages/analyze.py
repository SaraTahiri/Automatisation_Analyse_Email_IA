import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import pandas as pd
import sys
from pathlib import Path

# Ajouter le chemin pour les imports
sys.path.append(str(Path(__file__).parent.parent))
from utils.email_analyzer import EmailAnalyzer

st.set_page_config(page_title="Analyse", page_icon="🔍", layout="wide")

# Initialiser l'analyseur
@st.cache_resource
def get_analyzer():
    return EmailAnalyzer()

analyzer = get_analyzer()

st.title("🔍 Analyse IA en temps réel")

# Récupérer les données de la session
email_content = st.session_state.get('email_content', '')
model_type = st.session_state.get('model_type', 'ensemble')
filename = st.session_state.get('filename', 'Non spécifié')

if not email_content:
    st.warning("Aucun email à analyser. Veuillez d'abord uploader un email.")
    if st.button("📤 Aller à l'upload"):
        st.switch_page("pages/upload.py")
    st.stop()

# Section d'analyse
st.subheader(f"📨 Analyse de: {filename}")

col1, col2 = st.columns([2, 1])

with col1:
    with st.expander("📄 Voir le contenu de l'email"):
        st.text(email_content[:5000] + ("..." if len(email_content) > 5000 else ""))

with col2:
    st.write("**Paramètres d'analyse:**")
    st.write(f"📊 Modèle utilisé: **{model_type.upper()}")
    st.write(f"📏 Longueur: **{len(email_content)}** caractères")

# Bouton pour lancer l'analyse
if st.button("🚀 Lancer l'analyse complète", type="primary", use_container_width=True):
    with st.spinner("🧠 L'IA analyse l'email avec vos modèles entraînés..."):
        # Analyse avec vos modèles
        result = analyzer.analyze(email_content, model_type)
        
        # Afficher les résultats
        st.divider()
        
        # Header avec résultat
        classification = result['classification']
        confidence = result['confidence']
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Score de confiance",
                f"{confidence:.1%}",
                delta=f"Modèle: {model_type.upper()}"
            )
        
        with col2:
            risk_color = classification['color']
            st.markdown(
                f"<h2 style='color:{risk_color}; text-align: center;'>{classification['label']}</h2>",
                unsafe_allow_html=True
            )
        
        with col3:
            st.metric(
                "Niveau de risque",
                classification['level'],
                delta_color="inverse"
            )
        
        # Jauge de risque interactive
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=confidence * 100,
            title={'text': "Niveau de risque"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': classification['color']},
                'steps': [
                    {'range': [0, 40], 'color': "lightgreen"},
                    {'range': [40, 70], 'color': "yellow"},
                    {'range': [70, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "black", 'width': 4},
                    'thickness': 0.75,
                    'value': 70
                }
            }
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
        
        # Onglets détaillés
        tab1, tab2, tab4 = st.tabs([
            "📊 Prédictions détaillées", 
            "🔍 Features analysées",
            "💡 Recommandations"
        ])
        
        with tab1:
            st.subheader("Prédictions par modèle")
            
            # Graphique des prédictions
            predictions = result['predictions']
            models = list(predictions.keys())
            scores = list(predictions.values())
            
            fig2 = go.Figure(data=[
                go.Bar(
                    x=models,
                    y=scores,
                    text=[f"{score:.1%}" for score in scores],
                    textposition='auto',
                    marker_color=['#FF6B6B', '#4ECDC4', '#45B7D1']
                )
            ])
            fig2.update_layout(
                title="Scores de confiance par modèle",
                yaxis=dict(range=[0, 1], tickformat=".0%"),
                xaxis_title="Modèle",
                yaxis_title="Score"
            )
            st.plotly_chart(fig2, use_container_width=True)
            
            # Tableau détaillé
            pred_df = pd.DataFrame({
                'Modèle': models,
                'Score': scores,
                'Seuil': [0.5] * len(models),
                'Prédiction': ['Phishing' if score > 0.5 else 'Légitime' for score in scores]
            })
            st.dataframe(pred_df, use_container_width=True)
        
        with tab2:
            st.subheader("Features extraites de l'email")
            
            features = result['features']
            features_df = pd.DataFrame({
                'Feature': list(features.keys()),
                'Valeur': list(features.values())
            })
            
            # Graphique des features importantes
            fig3 = px.bar(
                features_df.head(10),
                x='Valeur',
                y='Feature',
                orientation='h',
                color='Valeur',
                color_continuous_scale='Reds'
            )
            fig3.update_layout(height=400)
            st.plotly_chart(fig3, use_container_width=True)
            
            # Tableau complet
            st.dataframe(features_df, use_container_width=True)
        
        
        with tab4:
            st.subheader("Recommandations d'action")
            
            action = classification['action']
            recommendation = classification['recommendation']
            
            if action == "BLOCK":
                st.error(f"## 🚨 {recommendation}")
                st.write("**Actions immédiates:**")
                st.write("1. Bloquer l'email immédiatement")
                st.write("2. Signaler comme phishing")
                st.write("3. Mettre en quarantaine si déjà reçu")
                st.write("4. Notifier les utilisateurs potentiellement affectés")
            
            elif action == "QUARANTINE":
                st.warning(f"## ⚠️ {recommendation}")
                st.write("**Actions recommandées:**")
                st.write("1. Mettre en quarantaine pour analyse")
                st.write("2. Vérifier manuellement le contenu")
                st.write("3. Contacter l'expéditeur légitime si doute")
                st.write("4. Surveiller les activités similaires")
            
            else:
                st.success(f"## ✅ {recommendation}")
                st.write("**Vérifications standard:**")
                st.write("1. Vérifier les pièces jointes si présentes")
                st.write("2. S'assurer que l'expéditeur est connu")
                st.write("3. Autoriser la livraison normale")
            
            # Exporter les résultats
            st.divider()
            if st.button("📥 Exporter le rapport complet", use_container_width=True):
                # Préparer le rapport
                report = f"""
                RAPPORT D'ANALYSE EMAIL
                ======================
                Fichier: {filename}
                Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                Modèle utilisé: {model_type.upper()}
                
                RÉSULTAT:
                ---------
                Classification: {classification['label']}
                Niveau de risque: {classification['level']}
                Score de confiance: {confidence:.1%}
                Recommandation: {recommendation}
                
                DÉTAILS DES MODÈLES:
                --------------------
                """
                for model, score in predictions.items():
                    report += f"{model.upper()}: {score:.1%}\n"
                
                st.download_button(
                    label="💾 Télécharger le rapport",
                    data=report,
                    file_name=f"rapport_{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
        
        # Historique (simplifié)
        st.divider()
        if st.button("💾 Enregistrer dans l'historique", type="secondary"):
            # Ici vous pourriez sauvegarder dans une base de données
            st.success("Analyse enregistrée dans l'historique")
            st.switch_page("pages/history.py")
else:
    st.info("👆 Cliquez sur le bouton pour lancer l'analyse avec vos modèles IA")