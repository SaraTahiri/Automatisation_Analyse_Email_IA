import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import json
import sys
from pathlib import Path
import os

st.set_page_config(page_title="Historique", page_icon="📊")

st.title("📊 Historique des analyses")

# Chemin vers le fichier d'historique
history_file = Path(__file__).parent.parent / "data" / "analysis_history.json"

# Charger l'historique existant ou créer un exemple
if history_file.exists():
    with open(history_file, 'r') as f:
        history_data = json.load(f)
else:
    # Données de démo basées sur vos résultats
    history_data = [
        {
            "id": i,
            "date": (datetime.now() - timedelta(days=i)).isoformat(),
            "filename": f"email_{i}.eml",
            "prediction": "PHISHING" if i % 3 == 0 else "LEGITIMATE",
            "confidence": 0.82 if i % 3 == 0 else 0.25,
            "model_used": ["rf", "lr", "dl", "ensemble"][i % 4],
            "risks": [
                {
                    "type": "SUSPICIOUS_KEYWORDS" if i % 3 == 0 else "LEGITIMATE_FORMAT",
                    "severity": "HIGH" if i % 3 == 0 else "LOW",
                    "description": "Mots suspects détectés" if i % 3 == 0 else "Format normal"
                }
            ]
        }
        for i in range(20)
    ]

df = pd.DataFrame(history_data)
df['date'] = pd.to_datetime(df['date'])

# Filtres
st.sidebar.header("🔍 Filtres")

date_range = st.sidebar.date_input(
    "Période",
    value=(datetime.now() - timedelta(days=7), datetime.now())
)

prediction_filter = st.sidebar.multiselect(
    "Type d'email",
    ["PHISHING", "SUSPICIOUS", "LEGITIMATE", "SPAM"],
    default=["PHISHING", "LEGITIMATE"]
)

model_filter = st.sidebar.multiselect(
    "Modèle utilisé",
    df['model_used'].unique().tolist(),
    default=df['model_used'].unique().tolist()
)

# Appliquer les filtres
if len(date_range) == 2:
    start_date, end_date = date_range
    filtered_df = df[
        (df['date'].dt.date >= start_date) & 
        (df['date'].dt.date <= end_date) &
        (df['prediction'].isin(prediction_filter)) &
        (df['model_used'].isin(model_filter))
    ]
else:
    filtered_df = df[
        (df['prediction'].isin(prediction_filter)) &
        (df['model_used'].isin(model_filter))
    ]

# Statistiques
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total analyses", len(df))

with col2:
    phishing_count = len(df[df['prediction'] == 'PHISHING'])
    st.metric("Phishing détectés", phishing_count)

with col3:
    avg_confidence = df['confidence'].mean()
    st.metric("Confiance moyenne", f"{avg_confidence:.1%}")

with col4:
    st.metric("Analyses filtrées", len(filtered_df))

# Tableau des résultats
st.subheader(f"📋 Résultats ({len(filtered_df)} analyses)")

for _, row in filtered_df.sort_values('date', ascending=False).iterrows():
    risk_color = {
        "PHISHING": "🔴",
        "SUSPICIOUS": "🟡",
        "LEGITIMATE": "🟢",
        "SPAM": "🟠"
    }.get(row['prediction'], "⚪")
    
    with st.expander(f"{risk_color} {row['filename']} - {row['date'].strftime('%d/%m/%Y %H:%M')}"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.write(f"**Fichier:** `{row['filename']}`")
            st.write(f"**Résultat:** **{row['prediction']}**")
            st.write(f"**Confiance:** {row['confidence']:.1%}")
            st.write(f"**Modèle:** {row['model_used'].upper()}")
        
        with col2:
            st.write(f"**Date:** {row['date'].strftime('%d/%m/%Y %H:%M:%S')}")
            st.write("**Risques détectés:**")
            if 'risks' in row and row['risks']:
                for risk in row['risks']:
                    st.write(f"- {risk['type']} ({risk.get('severity', 'N/A')})")
            else:
                st.write("Aucun risque spécifique")
            
            # Bouton pour revoir l'analyse
            if st.button("🔍 Voir détails", key=f"view_{row['id']}"):
                st.session_state['selected_analysis'] = row.to_dict()
                st.switch_page("pages/analyze.py")

# Graphique des tendances
st.divider()
st.subheader("📈 Tendances temporelles")

# Grouper par jour
daily_stats = filtered_df.copy()
daily_stats['date_only'] = daily_stats['date'].dt.date
daily_stats = daily_stats.groupby('date_only').agg({
    'id': 'count',
    'confidence': 'mean',
    'prediction': lambda x: (x == 'PHISHING').sum()
}).reset_index()

if not daily_stats.empty:
    col1, col2 = st.columns(2)
    
    with col1:
        # Graphique du nombre d'analyses par jour
        fig1 = px.line(
            daily_stats,
            x='date_only',
            y='id',
            title="Analyses par jour",
            labels={'date_only': 'Date', 'id': "Nombre d'analyses"}
        )
        st.plotly_chart(fig1, use_container_width=True)
    
    with col2:
        # Graphique du taux de phishing par jour
        daily_stats['phishing_rate'] = daily_stats['prediction'] / daily_stats['id']
        fig2 = px.line(
            daily_stats,
            x='date_only',
            y='phishing_rate',
            title="Taux de phishing par jour",
            labels={'date_only': 'Date', 'phishing_rate': 'Taux phishing'}
        )
        fig2.update_layout(yaxis_tickformat=".0%")
        st.plotly_chart(fig2, use_container_width=True)

# Export des données
st.divider()
if st.button("📤 Exporter toutes les données", use_container_width=True):
    csv = filtered_df.to_csv(index=False)
    st.download_button(
        label="💾 Télécharger CSV",
        data=csv,
        file_name=f"historique_analyses_{datetime.now().strftime('%Y%m%d')}.csv",
        mime="text/csv"
    )