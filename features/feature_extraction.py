import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "urgent", "verify", "account", "password",
    "confirm", "security", "update", "login"
]

DANGEROUS_EXTENSIONS = [".exe", ".zip", ".js", ".scr", ".bat"]


def extract_text_features(text):
    features = {}

    words = text.split()

    features["text_length"] = len(text)
    features["word_count"] = len(words)
    features["suspicious_word_count"] = sum(
        1 for w in words if w in SUSPICIOUS_WORDS
    )

    return features


def extract_url_features(text):
    features = {}

    urls = re.findall(r'http[s]?://\S+', text)

    features["url_count"] = len(urls)
    features["https_url_count"] = sum(
        1 for url in urls if url.startswith("https")
    )

    domains = [urlparse(url).netloc for url in urls]
    features["unique_domains"] = len(set(domains))

    return features


def extract_header_features(email_data):
    features = {}

    features["spf_present"] = int(
        email_data.get("Received-SPF") is not None
    )
    features["dkim_present"] = int(
        email_data.get("DKIM-Signature") is not None
    )
    features["dmarc_present"] = int(
        email_data.get("Authentication-Results") is not None
    )

    return features



def extract_attachment_features(attachments):
    features = {}

    features["attachment_count"] = len(attachments)
    features["dangerous_attachment"] = int(
        any(att["filename"] and
            any(att["filename"].endswith(ext) for ext in DANGEROUS_EXTENSIONS)
            for att in attachments)
    )

    return features


def extract_all_features(email_data, clean_text):
    features = {}

    features.update(extract_text_features(clean_text))
    features.update(extract_url_features(clean_text))
    features.update(extract_header_features(email_data))
    features.update(
        extract_attachment_features(email_data.get("Attachments", []))
    )

    return features

