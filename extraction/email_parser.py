# Import du module email (standard Python)
# Il permet de manipuler, parser et analyser des e-mails
import email

# policy.default définit la façon moderne de parser les e-mails
from email import policy

# BytesParser sert à lire un e-mail à partir de données binaires (.eml)
from email.parser import BytesParser

# os peut servir à manipuler les chemins de fichiers
import os


def parse_email(file_path):
    # Ouverture du fichier email au format binaire
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    email_data = {}

    # =========================
    # HEADERS CLASSIQUES (RFC 5322)
    # =========================
    email_data['From'] = msg['From']
    email_data['To'] = msg['To']
    email_data['Subject'] = msg['Subject']
    email_data['Date'] = msg['Date']
    email_data['Message-ID'] = msg['Message-ID']
    email_data['Reply-To'] = msg['Reply-To']

    # =========================
    # HEADERS DE SÉCURITÉ EMAIL
    # (SPF, DKIM, DMARC, ARC)
    # =========================
    email_data['Authentication-Results'] = msg['Authentication-Results']
    email_data['Received-SPF'] = msg['Received-SPF']
    email_data['DKIM-Signature'] = msg['DKIM-Signature']
    email_data['ARC-Seal'] = msg['ARC-Seal']
    email_data['ARC-Message-Signature'] = msg['ARC-Message-Signature']
    email_data['ARC-Authentication-Results'] = msg['ARC-Authentication-Results']

    # =========================
    # BODY
    # =========================
    email_data['Body_Text'] = ""
    email_data['Body_HTML'] = ""

    # =========================
    # ATTACHMENTS
    # =========================
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            if content_type == "text/plain" and disposition != "attachment":
                email_data['Body_Text'] += part.get_content()

            elif content_type == "text/html" and disposition != "attachment":
                email_data['Body_HTML'] += part.get_content()

            elif disposition == "attachment":
                attachments.append({
                    "filename": part.get_filename(),
                    "content_type": content_type,
                    "size": len(part.get_payload(decode=True))
                })
    else:
        email_data['Body_Text'] = msg.get_content()

    email_data['Attachments'] = attachments

    return email_data
