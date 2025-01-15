import requests
from bs4 import BeautifulSoup

def google_search(name, num_results=10):
    query = f"{name}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
    }
    url = f"https://www.google.com/search?q={query.replace(' ', '+')}&num={num_results}"

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Erreur lors de la recherche : {response.status_code}")
        return None

def extract_info(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    results = []

    for g in soup.find_all('div', class_='tF2Cxc'):
        title_element = g.find('h3')
        link_element = g.find('a', href=True)

        if title_element and link_element:
            title = title_element.get_text()
            link = link_element['href']
            results.append((title, link))
    return results
