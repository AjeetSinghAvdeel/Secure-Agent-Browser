from bot import get_html
from scanner import scan_page

RISK_THRESHOLD = 70

def run(url):
    driver, html = get_html(url)

    result = scan_page(html)

    print("Risk:", result["risk"])
    print("Reasons:")
    for r in result["reasons"]:
        print("-", r)

    if result["risk"] >= RISK_THRESHOLD:
        print("BLOCKED")
        driver.save_screenshot("../logs/blocked.png")
    else:
        print("SAFE")

    driver.quit()

if __name__ == "__main__":
    run("https://example.com")
