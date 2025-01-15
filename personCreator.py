import requests
from flask import send_file
from io import BytesIO

def generate_image():
    url = 'https://thispersondoesnotexist.com/'
    response = requests.get(url)

    if response.status_code == 200:
        img = BytesIO(response.content)
        img.seek(0)
        return send_file(img, mimetype='image/jpeg')
    else:
        return 'Error generating random image.'
