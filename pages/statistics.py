import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

st.set_page_config(page_title="Statistiques", page_icon="📈")

st.title("📈 Tableau de bord statistique")

# Générer des données de démo
dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
np.random.seed(42)

data = pd.DataFrame({
    'date': dates,
    'legitimate': np.random.randint(80, 150, 30),
    'phishing': np.random.randint(20, 60, 30),
    'spam': np.random.randint(10, 40, 30),
    'users': np.random.randint(50, 100, 30)
})

# Top domaines suspects
top_domains = pd.DataFrame({
    'domain': [
        'secure-bank-update.com',
        'paypal-verify.net',
        'microsoft-security.xyz',
        'amazon-payment.com',
        'google-account-recovery.io'
    ],
    'count': [42, 38, 31, 28, 25]
})

# Layout en colonnes
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Tendances quotidiennes")
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=data['date'], y=data['phishing'],
        mode='lines+markers',
        name='Phishing',
        line=dict(color='red', width=3)
    ))
    fig.add_trace(go.Scatter(
        x=data['date'], y=data['legitimate'],
        mode='lines',
        name='Légitimes',
        line=dict(color='green', width=2)
    ))
    
    fig.update_layout(
        height=300,
        xaxis_title="Date",
        yaxis_title="Nombre d'emails",
        hovermode='x unified'
    )
    
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("🎯 Performance des modèles")
    
    models = ['Random Forest', 'Logistic Regression', 'Deep Learning']
    accuracy = [0.85, 0.78, 0.82]
    precision = [0.87, 0.81, 0.83]
    recall = [0.83, 0.75, 0.80]
    
    fig2 = go.Figure(data=[
        go.Bar(name='Accuracy', x=models, y=accuracy, marker_color='#1f77b4'),
        go.Bar(name='Precision', x=models, y=precision, marker_color='#ff7f0e'),
        go.Bar(name='Recall', x=models, y=recall, marker_color='#2ca02c')
    ])
    
    fig2.update_layout(
        height=300,
        barmode='group',
        yaxis=dict(range=[0, 1])
    )
    
    st.plotly_chart(fig2, use_container_width=True)

# Distribution des emails
st.subheader("📧 Distribution des emails")

col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    total = data[['legitimate', 'phishing', 'spam']].sum()
    
    fig3 = go.Figure(data=[go.Pie(
        labels=['Légitimes', 'Phishing', 'Spam'],
        values=total.values,
        hole=0.3,
        marker_colors=['green', 'red', 'orange']
    )])
    
    fig3.update_layout(height=300)
    st.plotly_chart(fig3, use_container_width=True)

with col2:
    st.metric("Total emails", f"{total.sum():,}")
    st.metric("Taux phishing", f"{(total['phishing'] / total.sum() * 100):.1f}%")
    st.metric("Précision", "92.3%")

with col3:
    st.metric("Faux positifs", "2.4%")
    st.metric("Faux négatifs", "1.8%")
    st.metric("Temps moyen", "0.8s")

# Top domaines suspects
st.subheader("🌐 Top 5 domaines malveillants")

fig4 = px.bar(
    top_domains,
    x='count',
    y='domain',
    orientation='h',
    color='count',
    color_continuous_scale='Reds'
)

fig4.update_layout(
    height=300,
    xaxis_title="Nombre d'occurrences",
    yaxis_title="Domaine"
)

st.plotly_chart(fig4, use_container_width=True)

# Tableau détaillé
st.subheader("📋 Données détaillées")

with st.expander("Voir les données brutes"):
    st.dataframe(
        data.assign(
            total=lambda x: x['legitimate'] + x['phishing'] + x['spam'],
            phishing_rate=lambda x: (x['phishing'] / x['total'] * 100).round(1)
        ).tail(10),
        use_container_width=True
    )

# Téléchargement des données
st.download_button(
    label="📥 Télécharger les données",
    data=data.to_csv(index=False).encode('utf-8'),
    file_name=f"phishing_stats_{datetime.now().strftime('%Y%m%d')}.csv",
    mime="text/csv"
)