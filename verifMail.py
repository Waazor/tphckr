import re
import smtplib
import dns.resolver


def validate_email_format(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None


def get_mx_records(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_records = [record.exchange.to_text() for record in records]
        return mx_records
    except Exception as e:
        print(f"Erreur lors de la recherche des enregistrements MX : {e}")
        return []


def verify_email(email):
    if not validate_email_format(email):
        return "Format d'adresse e-mail invalide."

    domain = email.split('@')[1]
    mx_records = get_mx_records(domain)
    if not mx_records:
        return "Le domaine n'a pas d'enregistrement MX valide."

    try:
        smtp_server = smtplib.SMTP(mx_records[0])
        smtp_server.helo()
        smtp_server.mail('test@example.com')
        code, message = smtp_server.rcpt(email)
        smtp_server.quit()

        if code == 250:
            return "L'adresse e-mail existe."
        else:
            return "L'adresse e-mail n'existe pas."
    except Exception as e:
        return f"Erreur lors de la vérification SMTP : {e}"

