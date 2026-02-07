from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time

def get_html(url):
    options = Options()
    options.add_argument("--start-maximized")

    driver = webdriver.Chrome(options=options)
    driver.get(url)
    time.sleep(3)

    html = driver.page_source
    return driver, html
