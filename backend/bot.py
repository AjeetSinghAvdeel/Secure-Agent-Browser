from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import json


# --------------------------------------------------
# Browser Instrumentation Script (Injected JS)
# --------------------------------------------------
JS_PROBE = """
(() => {
    if (window.__secureAgentProbeInstalled) return;
    window.__secureAgentProbeInstalled = true;

    window.__secureAgentSignals = {
        domMutations: 0,
        suspiciousOverlays: 0,
        clickInterceptors: 0,
        eventHijacks: 0
    };

    // ----------------------------
    // DOM Mutation Observer
    // ----------------------------
    const observer = new MutationObserver((mutations) => {
        for (const m of mutations) {
            if (m.addedNodes.length > 0) {
                window.__secureAgentSignals.domMutations += m.addedNodes.length;
            }
        }
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });

    // ----------------------------
    // Overlay Detection
    // ----------------------------
    const scanOverlays = () => {
        const els = Array.from(document.querySelectorAll('*'));
        els.forEach(el => {
            const style = window.getComputedStyle(el);
            const z = parseInt(style.zIndex || '0', 10);

            if (
                (style.position === 'fixed' || style.position === 'absolute') &&
                z >= 1000 &&
                (style.opacity === '0' || style.opacity < 0.2)
            ) {
                window.__secureAgentSignals.suspiciousOverlays++;
            }
        });
    };

    setInterval(scanOverlays, 2000);

    // ----------------------------
    // Click Interception Detection
    // ----------------------------
    document.addEventListener(
        'click',
        (e) => {
            if (e.defaultPrevented) {
                window.__secureAgentSignals.clickInterceptors++;
            }
        },
        true
    );

    // ----------------------------
    // Event Hijack Detection
    // ----------------------------
    const originalAddEventListener = EventTarget.prototype.addEventListener;

    EventTarget.prototype.addEventListener = function(type, listener, options) {
        if (type === 'click' || type === 'mousedown') {
            window.__secureAgentSignals.eventHijacks++;
        }
        return originalAddEventListener.call(this, type, listener, options);
    };
})();
"""


# --------------------------------------------------
# Main Browser Loader
# --------------------------------------------------
def get_html(url):
    options = Options()
    options.add_argument("--start-maximized")

    driver = webdriver.Chrome(options=options)

    driver.get(url)

    # Inject behavior probe
    driver.execute_script(JS_PROBE)

    html_data = ""
    behavior_data = {}

    MONITOR_TIME = 12
    INTERVAL = 3
    checks = int(MONITOR_TIME / INTERVAL)

    for i in range(checks):
        time.sleep(INTERVAL)

        html_data += f"\n<!-- DOM CHECK {i+1} -->\n"
        html_data += driver.page_source

        # Pull behavior signals
        try:
            behavior_data = driver.execute_script(
                "return window.__secureAgentSignals || {};"
            )
        except Exception:
            behavior_data = {}

    return driver, {
        "html": html_data,
        "behavior": behavior_data
    }
