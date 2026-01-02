"""
Module de prétraitement des emails
Phase 2 - PFA : Automatisation de l’analyse de sécurité des emails
"""

import re
import html
import base64


def decode_base64(text):
    """
    Décodage Base64 si nécessaire
    """
    try:
        return base64.b64decode(text).decode('utf-8', errors='ignore')
    except Exception:
        return text


def clean_text(text):
    """
    Nettoyage et normalisation du texte email
    """
    if not text:
        return ""

    # Décodage des entités HTML
    text = html.unescape(text)

    # Suppression des balises HTML
    text = re.sub(r'<[^>]+>', ' ', text)

    # Suppression des URLs
    text = re.sub(r'http\S+|www\S+', ' ', text)

    # Mise en minuscules
    text = text.lower()

    # Suppression des caractères non alphanumériques
    text = re.sub(r'[^a-z0-9\s]', ' ', text)

    # Suppression des espaces multiples
    text = re.sub(r'\s+', ' ', text)

    return text.strip()
