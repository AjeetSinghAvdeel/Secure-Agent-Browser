import sys
import os
from bot import get_html
from scanner import scan_page


# Risk thresholds
LOW_RISK = 40
HIGH_RISK = 70


# Trusted websites (Whitelist)
WHITELIST = [
    "google.com",
    "github.com",
    "youtube.com",
    "microsoft.com",
    "openai.com",
    "wikipedia.org"
]


def is_whitelisted(url):

    for site in WHITELIST:
        if site in url.lower():
            return True

    return False


def run(url):

    # -----------------------------
    # WHITELIST CHECK
    # -----------------------------

    if is_whitelisted(url):

        print("\n✅ TRUSTED WEBSITE")
        print("Skipping security scan for:", url)
        return


    # Load page
    driver, html = get_html(url)

    # Scan page
    result = scan_page(html)

    # Display result
    print("\n🔍 Scan Result")
    print("Risk:", result["risk"])
    print("Reasons:")

    for r in result["reasons"]:
        print("-", r)


    # -----------------------------
    # USER CONFIRMATION SYSTEM
    # -----------------------------

    risk = result["risk"]


    # LOW RISK
    if risk < LOW_RISK:

        print("\n✅ SAFE - Low Risk")


    # MEDIUM RISK
    elif LOW_RISK <= risk < HIGH_RISK:

        print("\n⚠️ WARNING: Suspicious Page Detected")
        print("Risk Score:", risk)

        choice = input("Do you want to continue? (yes/no): ").strip().lower()


        if choice in ["yes", "y"]:

            print("➡️ User allowed access.")


        else:

            print("🚨 Access Blocked by User Decision")

            driver.execute_script("""
                document.body.innerHTML =
                "<h1 style='color:red; text-align:center; margin-top:20%'>" +
                "⚠️ ACCESS BLOCKED BY USER" +
                "</h1>";
            """)

            os.makedirs("logs", exist_ok=True)
            driver.save_screenshot("logs/blocked.png")


    # HIGH RISK
    else:

        print("\n🚨 BLOCKED - High Risk")

        driver.execute_script("""
            document.body.innerHTML =
            "<h1 style='color:red; text-align:center; margin-top:20%'>" +
            "⚠️ ACCESS BLOCKED<br>High Risk Detected" +
            "</h1>";
        """)

        os.makedirs("logs", exist_ok=True)
        driver.save_screenshot("logs/blocked.png")


    # Close browser
    driver.quit()



if __name__ == "__main__":

    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        run("https://example.com")
