import sys
import os
from bot import get_html
from scanner import scan_page

RISK_THRESHOLD = 50


def run(url):
    driver, html = get_html(url)

    result = scan_page(html)

    print("\n🔍 Scan Result")
    print("Risk:", result["risk"])
    print("Reasons:")
    for r in result["reasons"]:
        print("-", r)

    if result["risk"] >= RISK_THRESHOLD:
        print("\n🚨 BLOCKED")

        os.makedirs("logs", exist_ok=True)
        driver.save_screenshot("logs/blocked.png")

    else:
        print("\n✅ SAFE")

    driver.quit()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        run("https://example.com")
