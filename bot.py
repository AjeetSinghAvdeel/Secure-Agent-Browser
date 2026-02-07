from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time


def get_html(url):

    options = Options()
    options.add_argument("--start-maximized")

    driver = webdriver.Chrome(options=options)

    # Load page
    driver.get(url)

    # -----------------------------
    # Live DOM Monitoring
    # -----------------------------

    html_data = ""

    MONITOR_TIME = 12   # total time to watch page (seconds)
    INTERVAL = 3        # check every 3 seconds

    checks = int(MONITOR_TIME / INTERVAL)

    for i in range(checks):

        time.sleep(INTERVAL)

        html_data += "\n<!-- DOM CHECK {} -->\n".format(i+1)
        html_data += driver.page_source


    return driver, html_data
