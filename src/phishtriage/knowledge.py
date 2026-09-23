"""Static triage knowledge: the lists an analyst carries in their head."""

from __future__ import annotations

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "t.ly",
    "lnkd.in", "s.id", "bl.ink", "short.io", "qrco.de", "tr.im",
}

# Extensions that are effectively "open and you are owned" in a mail context.
RISKY_EXTENSIONS = {
    ".html", ".htm", ".shtml", ".xhtml", ".hta", ".js", ".jse", ".vbs", ".vbe", ".wsf",
    ".ps1", ".bat", ".cmd", ".com", ".exe", ".scr", ".pif", ".cpl", ".msi",
    ".jar", ".lnk", ".iso", ".img", ".vhd", ".vhdx", ".one", ".chm", ".reg",
    ".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xll", ".svg", ".url", ".appx",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".ace", ".arj", ".tgz"}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "icu", "cfd", "rest", "gq",
    "tk", "ml", "cf", "ga", "work", "fit", "monster", "quest", "sbs", "buzz",
    "live", "shop", "online", "site", "store", "cam", "lol", "ru", "su", "cyou",
}

# Path/query words typical of a credential-harvesting page. Deliberately
# narrow: "invoice" or "account" alone fire on too much legitimate mail.
CREDENTIAL_WORDS = {
    "login", "signin", "sign-in", "logon", "verify", "verification", "password",
    "passwd", "authenticate", "recover", "unlock", "validate", "wallet", "mfa",
    "otp", "webmail", "owa", "office365", "o365", "sso", "credential",
}

URGENCY_WORDS = {
    "urgent", "immediately", "action required", "final notice", "suspend",
    "suspended", "deactivat", "expire", "expiring", "within 24 hours",
    "verify your account", "unusual activity", "unauthorized", "last warning",
    "payment failed", "overdue", "your account will be", "click here",
    "confirm your identity", "security alert", "password expires",
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "yahoo.com", "ymail.com", "icloud.com", "me.com", "aol.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.de", "mail.com", "yandex.ru",
    "yandex.com", "zoho.com", "mail.ru", "rediffmail.com", "tutanota.com",
}

# Brand keyword -> the registrable domains that brand genuinely sends from or
# hosts login pages on. Used for display-name spoofing and lookalike checks.
BRANDS: dict[str, set[str]] = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "outlook.com",
                  "live.com", "sharepoint.com", "office365.com", "onmicrosoft.com",
                  "microsoft365.com", "azure.com", "windows.net", "msauth.net", "msft.net"},
    "office365": {"microsoft.com", "office.com", "office365.com", "microsoftonline.com"},
    "outlook": {"outlook.com", "microsoft.com", "office.com", "live.com"},
    "onedrive": {"onedrive.com", "live.com", "microsoft.com", "sharepoint.com"},
    "sharepoint": {"sharepoint.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "icloud": {"icloud.com", "apple.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com", "gstatic.com"},
    "gmail": {"gmail.com", "google.com", "googlemail.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amazonses.com", "amazonaws.com"},
    "paypal": {"paypal.com", "paypal.co.uk", "paypal.me"},
    "netflix": {"netflix.com"},
    "dhl": {"dhl.com", "dhl.de", "dhl.co.uk"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "facebook": {"facebook.com", "facebookmail.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "meta": {"meta.com", "facebook.com", "facebookmail.com"},
    "hmrc": {"hmrc.gov.uk", "gov.uk"},
    "nhs": {"nhs.uk", "nhs.net"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "hsbc": {"hsbc.co.uk", "hsbc.com"},
    "lloyds": {"lloydsbank.com", "lloydsbank.co.uk"},
    "natwest": {"natwest.com"},
    "santander": {"santander.co.uk", "santander.com"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "adobe": {"adobe.com", "adobesign.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "wetransfer": {"wetransfer.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "zoom": {"zoom.us", "zoom.com"},
    "slack": {"slack.com"},
}

# Brands whose name is a common word or a substring of unrelated words: these
# only match as a whole hyphen/dot token ("dhl-parcel.top"), never inside one.
TOKEN_ONLY_BRANDS = {"dhl", "ups", "nhs", "hsbc", "meta", "apple", "zoom", "slack"}


def known_legit_domains() -> set[str]:
    legit: set[str] = set()
    for domains in BRANDS.values():
        legit |= domains
    return legit
