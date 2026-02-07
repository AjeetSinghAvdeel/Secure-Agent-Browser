from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import time

def get_html(url):
    chrome_options = Options()
    chrome_options.add_argument("--start-maximized")

    service = Service()
    driver = webdriver.Chrome(service=service, options=chrome_options)

    driver.get(url)
    time.sleep(3)  # allow page load

    html = driver.page_source

    return driver, html
