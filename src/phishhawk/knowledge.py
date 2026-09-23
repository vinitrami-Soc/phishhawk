"""Static triage knowledge: the lists an analyst carries in their head."""

from __future__ import annotations

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "t.ly",
    "lnkd.in", "s.id", "bl.ink", "short.io", "qrco.de", "tr.im", "geni.us", "vk.cc",
    "vk.sv", "clck.ru", "v.gd", "bit.do", "surl.li", "urlz.fr", "u.to", "tiny.one",
    "shorturl.asia", "t2m.io", "forms.gle",
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
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com", "wf.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "amex": {"americanexpress.com", "aexp.com"},
    "americanexpress": {"americanexpress.com", "aexp.com"},
    "usps": {"usps.com", "usps.gov"},
    "royalmail": {"royalmail.com"},
    "evri": {"evri.com"},
    "irs": {"irs.gov"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.de"},
    "walmart": {"walmart.com"},
    "twitter": {"twitter.com", "x.com"},
    "tiktok": {"tiktok.com"},
    "telegram": {"telegram.org", "t.me"},
    "yahoo": {"yahoo.com"},
    "godaddy": {"godaddy.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "ripple": {"ripple.com"},
    "trustwallet": {"trustwallet.com"},
    "norton": {"norton.com", "nortonlifelock.com", "gen.com"},
    "mcafee": {"mcafee.com"},
    "geeksquad": {"geeksquad.com", "bestbuy.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com"},
    "paytm": {"paytm.com"},
    "caixa": {"caixa.gov.br"},
    "itau": {"itau.com.br"},
    "bradesco": {"bradesco.com.br"},
    "correios": {"correios.com.br"},
}

# Brands whose name is a common word or a substring of unrelated words: these
# only match as a whole hyphen/dot token ("dhl-parcel.top"), never inside one.
TOKEN_ONLY_BRANDS = {"dhl", "ups", "nhs", "hsbc", "meta", "apple", "zoom", "slack", "chase", "amex",
                     "usps", "evri", "irs", "steam", "ripple", "sbi", "hdfc", "caixa", "itau", "telegram"}


def known_legit_domains() -> set[str]:
    legit: set[str] = set()
    for domains in BRANDS.values():
        legit |= domains
    return legit


# Display-name words that say "an organisation sent this". From a free-mail
# address they are a classic impersonation tell.
ORG_WORDS = {
    "bank", "team", "support", "service", "services", "security", "account", "accounts",
    "billing", "helpdesk", "admin", "administrator", "notification", "notifications",
    "it", "hr", "payroll", "delivery", "customer", "official", "department", "desk",
    "compliance", "finance", "webmail", "mailbox", "protocolo", "atendimento", "suporte",
    "soporte", "servicio", "kundenservice", "equipe", "equipo",
}

# Words that make a brand in the subject an account/transaction notice rather
# than, say, a news headline about the brand.
ACCOUNT_CONTEXT = {
    "account", "sign-in", "signin", "login", "password", "verify", "verification", "security",
    "suspend", "suspended", "locked", "unusual", "payment", "invoice", "billing", "subscription",
    "renew", "renewal", "refund", "delivery", "package", "parcel", "shipment", "wallet", "tokens",
    "reward", "prize", "storage", "mailbox", "document", "shared", "voicemail", "order", "conta",
    "cuenta", "konto", "compte", "alert", "notice", "confirm", "update",
}

# Hosting that costs an attacker nothing to stand up. Suffix match on the host.
FREE_HOSTING = (
    ".web.app", ".firebaseapp.com", ".pages.dev", ".workers.dev", ".r2.dev", ".netlify.app",
    ".vercel.app", ".glitch.me", ".github.io", ".blogspot.com", ".weebly.com", ".wixsite.com",
    ".webflow.io", ".square.site", ".godaddysites.com", ".000webhostapp.com", ".azurewebsites.net",
    ".web.core.windows.net", ".onrender.com", ".replit.app", ".repl.co", ".herokuapp.com",
    ".fly.dev", ".surge.sh", ".mybluehost.me", ".framer.website", ".carrd.co",
)
# Tunnels and IPFS gateways: almost never in legitimate business mail.
TUNNELS_AND_IPFS = (
    ".ngrok-free.app", ".ngrok.io", ".ngrok.app", ".trycloudflare.com", ".loca.lt",
    ".ipfs.dweb.link", ".ipfs.w3s.link", ".ipfs.nftstorage.link",
)
IPFS_GATEWAYS = {"ipfs.io", "cloudflare-ipfs.com", "gateway.pinata.cloud", "dweb.link", "w3s.link"}
# (host, path prefix) of file-sharing and form-builder links: the URL is an
# indicator even though the domain itself must never be blocked.
FILE_SHARING = (
    ("drive.google.com", ("/uc", "/file/", "/open")), ("docs.google.com", ("/forms/",)),
    ("storage.googleapis.com", ("/",)), ("firebasestorage.googleapis.com", ("/",)),
    ("sites.google.com", ("/",)), ("dropbox.com", ("/s/", "/scl/", "/t/")),
    ("dl.dropboxusercontent.com", ("/",)), ("1drv.ms", ("/",)), ("onedrive.live.com", ("/",)),
    ("we.tl", ("/",)), ("wetransfer.com", ("/downloads/",)), ("mega.nz", ("/",)),
    ("mediafire.com", ("/file/", "/download/")), ("forms.office.com", ("/",)), ("jotform.com", ("/",)),
)

# Lure phrases, matched in the subject and the visible body. Kept to phrases,
# not single words, so marketing copy does not trip them on its own.
LURES: dict[str, tuple[str, ...]] = {
    "credential": (
        "verify your account", "verify your identity", "confirm your identity", "confirm your account",
        "unusual sign-in", "unusual activity", "suspicious activity", "account will be suspended",
        "account has been suspended", "account has been locked", "update your payment",
        "update your billing", "mailbox is full", "storage is full", "password expires",
        "password will expire", "sign in to view", "shared a document with you",
        "you have received a voicemail", "new voicemail", "action required", "re-validate",
        "revalidate your", "keep your account", "avoid suspension", "within 24 hours",
    ),
    "prize": (
        "you have been selected", "you've been selected", "you have won", "you've won",
        "claim your", "free spins", "airdrop", "giveaway", "lottery", "jackpot", "gift card",
        "you are a winner", "you're a winner", "reward is waiting", "exclusive reward",
        "gutschein im wert von", "cartão presente", "tarjeta de regalo", "carte cadeau",
    ),
    "advance-fee": (
        "inheritance", "next of kin", "beneficiary", "dying bed", "million dollars", "million usd",
        "barrister", "diplomatic", "consignment", "compensation fund", "atm card", "western union",
        "moneygram", "transfer the sum", "unclaimed fund", "late client", "urgent response",
    ),
    "extortion": (
        "i hacked", "hacked your", "recorded you", "your webcam", "bitcoin wallet", "btc address",
        "compromising video", "adult website", "your device was infected",
    ),
    "delivery": (
        "package is pending", "parcel is pending", "delivery failed", "unable to deliver",
        "customs fee", "redelivery", "reschedule delivery", "shipment on hold", "delivery attempt",
        "we tried to reach you", "we were unable to deliver", "wir haben versucht, sie zu erreichen",
    ),
    "payment": (
        "overdue invoice", "payment failed", "payment declined", "bank details have changed",
        "new bank account", "outstanding balance", "wire transfer", "urgent payment",
        "payment made today", "process a payment", "buy gift cards", "gift cards for",
    ),
    "foreign-language": (
        "valores a receber", "parcela liberada", "encomenda pendente", "confirmar ahora",
        "verifique sua conta", "sua conta", "su cuenta", "verifique su", "konto gesperrt",
        "bestätigen sie", "votre compte", "vérifiez votre", "conta bloqueada", "cuenta bloqueada",
        "você ganhou", "has ganado", "sie haben gewonnen", "vous avez gagné", "reembolso",
        "atualize seus dados", "actualice sus datos",
    ),
    "qr-code": (
        "scan the qr code", "scan the qr", "scan this qr", "scan the code below", "qr code below",
        "qr code attached", "use your phone camera", "use your phone's camera", "scan with your phone",
    ),
    "callback": (
        "call us at", "call our support", "contact our billing", "if you did not authorize",
        "to cancel this", "has been renewed", "auto-renew", "renewed successfully",
        "subscription has been renewed", "order has been placed", "if you did not make this purchase",
    ),
}
