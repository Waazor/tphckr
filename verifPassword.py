import requests

def check_if_pwd_is_on_list(password):
    url = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt'
    page = requests.get(url)
    if password in page.text:
        return "Votre mot de passe est dans la liste des 10000 mot de passe les plus utilisés"
    else:
        return "Votre mot de passe n'est pas dans la liste des 10000 mot de passe les plus utilisés"
