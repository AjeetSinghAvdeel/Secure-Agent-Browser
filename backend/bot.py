from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time


# --------------------------------------------------
# Browser Instrumentation Script (Injected JS)
# --------------------------------------------------
JS_PROBE = """
(() => {
    if (window.__secureAgentProbeInstalled) return;
    window.__secureAgentProbeInstalled = true;

    const getDomain = (url) => {
        try { return new URL(url).hostname; } catch { return ""; }
    };

    window.__secureAgentSignals = {
        domMutations: 0,
        suspiciousOverlays: 0,
        clickInterceptors: 0,
        eventHijacks: 0,
        network: []
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
        document.querySelectorAll('*').forEach(el => {
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

    // ----------------------------
    // NETWORK INTERCEPTION (STEP 4)
    // ----------------------------

    // fetch()
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        const url = args[0]?.url || args[0];
        window.__secureAgentSignals.network.push({
            type: "fetch",
            url,
            domain: getDomain(url),
            method: args[1]?.method || "GET",
            crossOrigin: getDomain(url) !== location.hostname
        });
        return originalFetch.apply(this, args);
    };

    // XMLHttpRequest
    const originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this.__secureAgentUrl = url;
        this.__secureAgentMethod = method;
        return originalXHROpen.call(this, method, url, ...rest);
    };

    const originalXHRSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
        window.__secureAgentSignals.network.push({
            type: "xhr",
            url: this.__secureAgentUrl,
            domain: getDomain(this.__secureAgentUrl),
            method: this.__secureAgentMethod,
            crossOrigin: getDomain(this.__secureAgentUrl) !== location.hostname
        });
        return originalXHRSend.call(this, body);
    };

    // sendBeacon
    const originalBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function(url, data) {
        window.__secureAgentSignals.network.push({
            type: "beacon",
            url,
            domain: getDomain(url),
            method: "BEACON",
            crossOrigin: getDomain(url) !== location.hostname
        });
        return originalBeacon.call(this, url, data);
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

    # Inject probe
    driver.execute_script(JS_PROBE)

    html_data = ""
    behavior_data = {}
    network_data = []

    MONITOR_TIME = 12
    INTERVAL = 3
    checks = int(MONITOR_TIME / INTERVAL)

    for i in range(checks):
        time.sleep(INTERVAL)

        html_data += f"\n<!-- DOM CHECK {i+1} -->\n"
        html_data += driver.page_source

        try:
            signals = driver.execute_script(
                "return window.__secureAgentSignals || {};"
            )
            behavior_data = {
                k: v for k, v in signals.items() if k != "network"
            }
            network_data = signals.get("network", [])
        except Exception:
            behavior_data = {}
            network_data = []

    return driver, {
        "html": html_data,
        "behavior": behavior_data,
        "network": network_data
    }
