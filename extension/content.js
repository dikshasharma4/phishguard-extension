 function showBanner(score) {
    const existing = document.getElementById("phishguard-banner");
    if (existing) existing.remove();

    const banner = document.createElement("div");
    banner.id = "phishguard-banner";

    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.padding = "14px";
    banner.style.zIndex = "999999";
    banner.style.display = "flex";
    banner.style.justifyContent = "center";
    banner.style.alignItems = "center";
    banner.style.fontFamily = "Segoe UI, sans-serif";
    banner.style.color = "#fff";

    banner.style.boxShadow = "0 4px 15px rgba(0,0,0,0.3)";
    banner.style.borderRadius = "0 0 12px 12px";

    // 🎯 Color + Text
    const text = document.createElement("span");

    if (score <= 30) {
        banner.style.background = "linear-gradient(90deg, #00b09b, #96c93d)";
        text.innerText = `✅ Safe Website (${score})`;
    } else if (score <= 65) {
        banner.style.background = "linear-gradient(90deg, #f7971e, #ffd200)";
        text.innerText = `⚠️ Suspicious Site (${score})`;
    } else {
        banner.style.background = "linear-gradient(90deg, #ff416c, #ff4b2b)";
        text.innerText = `🚨 Dangerous Site (${score}) - Avoid entering data!`;
    }

    // ❌ Close button
    const closeBtn = document.createElement("span");
    closeBtn.innerText = "❌";
    closeBtn.style.marginLeft = "20px";
    closeBtn.style.cursor = "pointer";
    closeBtn.onclick = () => banner.remove();

    banner.appendChild(text);
    banner.appendChild(closeBtn);

    banner.style.transform = "translateY(-100%)";
    document.body.prepend(banner);

    setTimeout(() => {
        banner.style.transform = "translateY(0)";
    }, 100);
}
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "SHOW_RESULT") {
        showBanner(msg.score);
    }
});