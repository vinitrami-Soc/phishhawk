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
    "ledger": {"ledger.com"},
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
    # 2.0: the brands most phished in 2024-2026 industry reports, and the
    # banks, couriers and tax offices in the lures of the tuning data
    "booking": {"booking.com"},
    "airbnb": {"airbnb.com"},
    "okta": {"okta.com", "oktapreview.com", "okta-emea.com"},
    "docsend": {"docsend.com", "dropbox.com"},
    "canva": {"canva.com"},
    "intuit": {"intuit.com"},
    "quickbooks": {"intuit.com", "quickbooks.com"},
    "xero": {"xero.com"},
    "stripe": {"stripe.com"},
    "shopify": {"shopify.com"},
    "spotify": {"spotify.com"},
    "disneyplus": {"disneyplus.com", "disney.com"},
    "roblox": {"roblox.com"},
    "alibaba": {"alibaba.com", "aliexpress.com"},
    "aliexpress": {"aliexpress.com", "alibaba.com"},
    "revolut": {"revolut.com"},
    "venmo": {"venmo.com"},
    "cashapp": {"cash.app", "squareup.com"},
    "zelle": {"zellepay.com"},
    "citibank": {"citi.com", "citibank.com"},
    "capitalone": {"capitalone.com"},
    "mastercard": {"mastercard.com"},
    "webex": {"webex.com", "cisco.com"},
    "salesforce": {"salesforce.com"},
    "workday": {"workday.com", "myworkday.com"},
    "costco": {"costco.com"},
    "kucoin": {"kucoin.com"},
    "bybit": {"bybit.com"},
    "opensea": {"opensea.io"},
    "uniswap": {"uniswap.org"},
    "trezor": {"trezor.io"},
    "kraken": {"kraken.com"},
    "robinhood": {"robinhood.com"},
    "dpd": {"dpd.com", "dpd.co.uk", "dpd.de", "dpd.fr"},
    "aramex": {"aramex.com"},
    "postnl": {"postnl.nl"},
    "laposte": {"laposte.fr", "laposte.net"},
    "colissimo": {"colissimo.fr", "laposte.fr"},
    "chronopost": {"chronopost.fr"},
    "auspost": {"auspost.com.au"},
    "canadapost": {"canadapost.ca", "canadapost-postescanada.ca"},
    "inpost": {"inpost.pl", "inpost.co.uk", "inpost.eu"},
    "correos": {"correos.es"},
    "posteitaliane": {"poste.it", "posteitaliane.it"},
    "ameli": {"ameli.fr"},
    "adac": {"adac.de"},
    "sparkasse": {"sparkasse.de"},
    "commerzbank": {"commerzbank.de", "commerzbank.com"},
    "postbank": {"postbank.de"},
    "rabobank": {"rabobank.nl", "rabobank.com"},
    "abnamro": {"abnamro.nl", "abnamro.com"},
    "belastingdienst": {"belastingdienst.nl"},
    "tvlicensing": {"tvlicensing.co.uk"},
    "vodafone": {"vodafone.com", "vodafone.co.uk", "vodafone.de"},
    "nubank": {"nubank.com.br"},
    "mercadolivre": {"mercadolivre.com.br", "mercadolibre.com"},
    "serasa": {"serasa.com.br"},
    "incometax": {"incometax.gov.in", "gov.in"},
    "uidai": {"uidai.gov.in"},
    "axisbank": {"axisbank.com", "axisbank.co.in"},
    "kotak": {"kotak.com", "kotakbank.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "airtel": {"airtel.in", "airtel.com"},
    "unitedhealthcare": {"uhc.com", "unitedhealthcare.com"},
    "medicare": {"medicare.gov", "cms.gov"},
}

# Brands whose name is a common word or a substring of unrelated words: these
# only match as a whole hyphen/dot token ("dhl-parcel.top"), never inside one.
TOKEN_ONLY_BRANDS = {"dhl", "ups", "nhs", "hsbc", "meta", "apple", "zoom", "slack", "chase", "amex",
                     "usps", "evri", "irs", "steam", "ripple", "sbi", "hdfc", "caixa", "itau", "telegram",
                     "ledger", "okta", "canva", "xero", "stripe", "venmo", "zelle", "kraken", "dpd", "adac",
                     "ameli", "kotak", "airtel", "correos", "booking", "costco", "webex", "serasa", "roblox"}

# What a combosquat bolts onto a name: "outlooksecure", "paypal-billing-update",
# "example-corp-payroll", "taxascorreios". A domain that merely contains a name
# ("linuxmafia", "shagmail", "yahoogroups") is not a lookalike: on real mail
# those were the commonest lookalike false positives.
COMBO_WORDS = {
    # a domain name spelled into the label: paypal-com.top, www-paypal.com
    "com", "www", "net", "org", "http", "https", "site",
    # sign-in and remote-access lures: example-corp-mfa.top, microsoft-sso.com
    "mfa", "2fa", "sso", "otp", "vpn", "remote", "enrol", "enroll", "servicedesk", "o365", "m365",
    "sharepoint", "outlook",
    "secure", "security", "safe", "safety", "protect", "protection", "login", "logon", "signin", "sign",
    "auth", "verify", "verification", "validate", "validation", "confirm", "confirmation", "check",
    "account", "accounts", "acct", "profile", "update", "updates", "upgrade", "support", "service",
    "services", "help", "helpdesk", "desk", "center", "centre", "care", "resolution", "recovery", "recover",
    "restore", "unlock", "reset", "password", "billing", "bill", "bills", "pay", "payment", "payments",
    "invoice", "invoices", "refund", "refunds", "claim", "claims", "tax", "taxes", "fee", "fees", "renew",
    "renewal", "subscription", "online", "portal", "web", "webmail", "mail", "email", "app", "apps",
    "access", "alert", "alerts", "notice", "notification", "notifications", "notify", "info", "official",
    "team", "teams", "staff", "admin", "document", "documents", "docs", "doc", "file", "files", "share",
    "sharing", "drive", "cloud", "storage", "envelope", "delivery", "deliver", "track", "tracking",
    "parcel", "package", "shipment", "shipping", "express", "prime", "reward", "rewards", "gift", "bonus",
    "promo", "prize", "wallet", "crypto", "customer", "customers", "client", "member", "members", "user",
    "users", "group", "corp", "inc", "llc", "ltd", "holdings", "global", "intl", "international", "hr",
    "payroll", "finance", "accounting", "procurement", "legal", "benefits", "office", "bank", "banking",
    "card", "cards", "credit", "loan", "transfer", "id", "it", "us", "usa", "uk", "eu",
    # Portuguese and Spanish, for the Brazilian and Latin American lures in real phishing data
    "taxa", "taxas", "fatura", "boleto", "pagamento", "cliente", "conta", "seguro", "servico", "servicos",
    "atualizacao", "cuenta", "pago", "factura", "soporte",
}

# Country-code TLDs that are sold like generic ones and routinely abused.
# "yahoo.co.uk" and "santander.com.br" are the brands' own country sites;
# "paypal.co" and "netflix.tk" are not.
GENERIC_CCTLDS = {"co", "cc", "tk", "ml", "ga", "cf", "gq", "ws", "io", "me", "ly", "to", "su", "pw",
                  "cm", "nu", "tv", "ai", "sh", "gg", "la", "vc", "st", "cx", "ms", "fm", "am", "ru"}


_LEGIT: set[str] = set()


def known_legit_domains() -> set[str]:
    if not _LEGIT:
        for domains in BRANDS.values():
            _LEGIT.update(domains)
    return _LEGIT


def extend(brands: dict[str, list[str]] | None = None, lures: dict[str, list[str]] | None = None) -> None:
    """Add an organisation's own brands ({name: [domains]}) and lure phrases
    ({category: [phrases]}) to the built-in lists."""
    for name, domains in (brands or {}).items():
        BRANDS.setdefault(name, set()).update(domains)
    for category, phrases in (lures or {}).items():
        LURES[category] = tuple(dict.fromkeys(LURES.get(category, ()) + tuple(phrases)))
    _LEGIT.clear()
    from . import lookalike  # noqa: PLC0415 - lookalike imports this module

    lookalike.clear_caches()


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
        "photos and videos will be deleted", "your photos will be deleted", "storage limit", "icloud storage",
        "certificate expires", "your password has expired", "confirm your email address to avoid",
        "update your kyc", "kyc update", "kyc verification", "complete your kyc", "kyc is pending",
        "kyc has expired", "account will be blocked", "will be disconnected tonight",
        "electricity will be disconnected", "power will be disconnected",
    ),
    "prize": (
        "you have been selected", "you've been selected", "you have won", "you've won",
        "claim your", "free spins", "giveaway", "lottery", "jackpot", "gift card",
        "you are a winner", "you're a winner", "reward is waiting", "exclusive reward",
        "gutschein im wert von", "cartão presente", "tarjeta de regalo", "carte cadeau",
        "cadeaukaart", "wij verloten", "je hebt gewonnen", "hai vinto", "wir gratulieren",
    ),
    # Wallet drainers: the seed phrase is the account, and nothing legitimate
    # asks for it. Measured on the tuning sets: 0 of 2,625 legitimate emails.
    "crypto": (
        "seed phrase", "recovery phrase", "secret phrase", "secret recovery phrase", "mnemonic phrase",
        "12-word", "24-word", "airdrop", "claim your tokens", "connect your wallet", "validate your wallet",
        "synchronize your wallet", "sync your wallet", "verify your wallet", "wallet verification",
        "wallet will be", "your wallet has been",
    ),
    "gambling": (
        "free spins", "freispiele", "giros gratis", "rodadas grátis", "tiradas gratis",
        "tours gratuits", "welcome bonus", "deposit bonus", "no deposit", "jackpot",
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
        "payment overdue", "invoice is overdue", "update my direct deposit", "change my direct deposit",
        "change my payroll", "update my payroll", "new banking details", "tax documents are ready",
        "tax refund", "refund is pending",
    ),
    "foreign-language": (
        "valores a receber", "parcela liberada", "encomenda pendente", "confirmar ahora",
        "verifique sua conta", "sua conta", "su cuenta", "verifique su", "konto gesperrt",
        "bestätigen sie", "votre compte", "vérifiez votre", "conta bloqueada", "cuenta bloqueada",
        "você ganhou", "has ganado", "sie haben gewonnen", "vous avez gagné", "reembolso",
        "atualize seus dados", "actualice sus datos",
        # French, German, Dutch, Italian and Spanish credential and parcel lures
        "vérifiez votre", "confirmez votre", "votre colis", "notification de retard", "mettre à jour vos",
        "ihr zertifikat", "läuft in kürze ab", "ihr konto wird", "ihr paket", "aktualisieren sie ihre",
        "verifieer uw", "bevestig uw", "uw account", "uw pakket", "uw rekening",
        "il tuo account", "verifica il tuo", "il tuo pacco", "aggiorna i tuoi dati",
        "necesitamos su confirmación", "su paquete", "verifique su identidad",
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
