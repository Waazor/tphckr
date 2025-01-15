import threading
import requests

def send_request(url_to_spam):
    try:
        response = requests.get(url_to_spam)
        print(f"Code de réponse : {response.status_code}")
    except Exception as e:
        print(f"Erreur : {e}")


def spam_request(url_to_spam):
    threads = []
    for _ in range(10):
        thread = threading.Thread(target=send_request, args=(url_to_spam,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()
