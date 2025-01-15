import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def spam_email(send_to, object_mail, content_mail):

    msg = MIMEMultipart()
    msg['From'] = 'victorwilloteaux@gmail.com'
    msg['To'] = send_to
    msg['Subject'] = object_mail
    message = content_mail
    msg.attach(MIMEText(message, 'plain'))

    mailserver = smtplib.SMTP('smtp.gmail.com', 587)
    mailserver.ehlo()
    mailserver.starttls()
    mailserver.ehlo()

    mailserver.login('victorwilloteaux@gmail.com', os.getenv('PASSWORD_MAIL'))

    mailserver.sendmail('victorwilloteaux@gmail.com', send_to, msg.as_string())

    mailserver.quit()

    print("Email envoyé avec succès !")
    return True