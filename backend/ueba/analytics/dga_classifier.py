"""Supervised DGA Classification.

Trains a RandomForest classifier on hardcoded known-good and known-DGA
domains, then classifies new domains in the Pi-hole event pipeline.

If scikit-learn is unavailable, falls back to a simple heuristic scorer.

Flag type: 'dga_classifier'
MITRE: T1568.002 (Command and Control)
"""

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

from ueba.logging_config import get_logger
from ueba.analytics.base import BaseAnomalyDetector, AnomalyResult

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

_VOWELS = set("aeiou")
_COMMON_TLDS = {"com", "net", "org", "edu", "gov", "mil", "int", "io",
                "co", "uk", "de", "jp", "fr", "au", "br", "ca", "cn",
                "in", "ru", "us", "nl", "se", "no", "dk", "fi", "pl",
                "it", "es", "pt", "ch", "at", "be", "nz", "za", "mx"}

_HIGH_RISK_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club",
                   "work", "date", "loan", "win", "bid", "trade", "webcam",
                   "stream", "download", "review", "country", "racing", "crypt",
                   "host", "press", "site", "space", "website", "online",
                   "tech", "live", "gdn", "gmbh", "fit", "men", "kim", "party"}

# Common English bigrams for reference
_COMMON_BIGRAMS = {"th", "he", "in", "er", "an", "on", "at", "en", "nd",
                   "ti", "es", "or", "te", "of", "ed", "is", "it", "al",
                   "ar", "st", "to", "nt", "ng", "se", "ha", "as", "ou",
                   "io", "le", "ve", "co", "me", "de", "hi", "ri", "ro"}


def extract_features(domain: str) -> Dict[str, float]:
    """Extract DGA classification features from a domain name.

    Returns a dict with:
        domain_length, subdomain_count, digit_ratio, consonant_ratio,
        vowel_ratio, bigram_entropy, trigram_entropy, longest_word_length,
        tld_risk_score
    """
    if not domain:
        return {
            "domain_length": 0, "subdomain_count": 0, "digit_ratio": 0,
            "consonant_ratio": 0, "vowel_ratio": 0, "bigram_entropy": 0,
            "trigram_entropy": 0, "longest_word_length": 0,
            "tld_risk_score": 0,
        }

    lower = domain.lower().rstrip(".")
    parts = lower.split(".")

    domain_length = len(lower)
    subdomain_count = max(0, len(parts) - 2)  # minus SLD and TLD

    # TLD risk score
    tld = parts[-1] if len(parts) >= 2 else ""
    if tld in _HIGH_RISK_TLDS:
        tld_risk_score = 1.0
    elif tld in _COMMON_TLDS:
        tld_risk_score = 0.0
    else:
        tld_risk_score = 0.5

    # Analyze the main domain name (second-level + subdomains combined)
    name = "".join(parts[:-1]) if len(parts) >= 2 else lower
    if not name:
        return {
            "domain_length": domain_length, "subdomain_count": subdomain_count,
            "digit_ratio": 0, "consonant_ratio": 0, "vowel_ratio": 0,
            "bigram_entropy": 0, "trigram_entropy": 0,
            "longest_word_length": 0, "tld_risk_score": tld_risk_score,
        }

    alpha_chars = [c for c in name if c.isalpha()]
    digits = sum(1 for c in name if c.isdigit())

    digit_ratio = digits / len(name) if name else 0

    vowels = sum(1 for c in alpha_chars if c in _VOWELS)
    consonants = len(alpha_chars) - vowels
    vowel_ratio = vowels / len(alpha_chars) if alpha_chars else 0
    consonant_ratio = consonants / len(alpha_chars) if alpha_chars else 0

    # Bigram entropy
    bigrams = defaultdict(int)
    for i in range(len(name) - 1):
        bg = name[i:i + 2]
        if bg.isalpha():
            bigrams[bg] += 1
    total_bigrams = sum(bigrams.values())
    bigram_entropy = 0.0
    if total_bigrams > 0:
        for count in bigrams.values():
            prob = count / total_bigrams
            bigram_entropy -= prob * math.log2(prob)

    # Trigram entropy
    trigrams = defaultdict(int)
    for i in range(len(name) - 2):
        tg = name[i:i + 3]
        if tg.isalpha():
            trigrams[tg] += 1
    total_trigrams = sum(trigrams.values())
    trigram_entropy = 0.0
    if total_trigrams > 0:
        for count in trigrams.values():
            prob = count / total_trigrams
            trigram_entropy -= prob * math.log2(prob)

    # Longest contiguous alphabetic word length
    longest = 0
    current = 0
    for c in name:
        if c.isalpha():
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    longest_word_length = longest

    return {
        "domain_length": float(domain_length),
        "subdomain_count": float(subdomain_count),
        "digit_ratio": round(digit_ratio, 4),
        "consonant_ratio": round(consonant_ratio, 4),
        "vowel_ratio": round(vowel_ratio, 4),
        "bigram_entropy": round(bigram_entropy, 4),
        "trigram_entropy": round(trigram_entropy, 4),
        "longest_word_length": float(longest_word_length),
        "tld_risk_score": tld_risk_score,
    }


# ---------------------------------------------------------------------------
# Hardcoded training data: 100 known-good + 100 known-DGA domains
# ---------------------------------------------------------------------------

KNOWN_GOOD_DOMAINS = [
    "google.com", "facebook.com", "youtube.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "spotify.com",
    "zoom.us", "discord.com", "whatsapp.com", "telegram.org", "pinterest.com",
    "adobe.com", "dropbox.com", "slack.com", "shopify.com", "wordpress.org",
    "cloudflare.com", "akamai.com", "fastly.com", "digitalocean.com", "oracle.com",
    "salesforce.com", "ibm.com", "intel.com", "cisco.com", "vmware.com",
    "nginx.com", "apache.org", "docker.com", "kubernetes.io", "terraform.io",
    "python.org", "nodejs.org", "golang.org", "rust-lang.org", "ruby-lang.org",
    "mozilla.org", "chromium.org", "webkit.org", "linux.org", "ubuntu.com",
    "debian.org", "fedoraproject.org", "opensuse.org", "centos.org", "archlinux.org",
    "freebsd.org", "openbsd.org", "netbsd.org", "postgresql.org", "mysql.com",
    "mongodb.com", "redis.io", "elastic.co", "kafka.apache.org", "hadoop.apache.org",
    "spark.apache.org", "flutter.dev", "android.com", "reactjs.org", "vuejs.org",
    "angular.io", "svelte.dev", "tailwindcss.com", "getbootstrap.com", "jquery.com",
    "d3js.org", "threejs.org", "chartjs.org", "lodash.com", "axios.com",
    "expressjs.com", "fastify.dev", "django.org", "flask.org", "laravel.com",
    "rubyonrails.org", "spring.io", "kubernetes.io", "ansible.com", "puppet.com",
    "chef.io", "jenkins.io", "gitlab.com", "bitbucket.org", "atlassian.com",
    "jetbrains.com", "visualstudio.com", "eclipse.org", "code.visualstudio.com", "vim.org",
]

DGA_DOMAINS = [
    "aefae2c3.net", "1b2a3c4d.com", "x9z8y7w6.biz", "pqrstuvw.xyz",
    "hjklmnop.click", "qwertzxcv.ml", "asdfghjkl.tk", "zxcvbnmas.ga",
    "poiuytrew.cf", "mnbvcxzlk.gq", "df8g7h6j5.info", "k3m9r2t5.work",
    "w7e4r1t8.date", "s2d6f8g9.bid", "h4j7k1l0.trade",
    "ab12cd34ef.ru", "xy98zw76vu.cn", "qp45rt89sg.xyz", "ln67km90jh.top",
    "vc32xb45nm.host", "fgh789jkl.party", "tyu456bnm.space", "zxc123qwe.site",
    "rty789uio.press", "mki876nhy.online", "asd567fgh.website", "lkj432mnb.tech",
    "bvc890xzw.live", "poi123ytr.stream", "wer456sdf.download",
    "cxz789ertg.com", "bvn456mjkp.net", "fgh123qazw.org", "vbn890yuiop.info",
    "rty567cvbnm.xyz", "plm234oknij.work", "wsx890edcrf.date", "qaz456ujml.bid",
    "ikm789rfvbn.trade", "edc123tgbnh.ml", "tgb456yhnju.ga", "ujm789iklo.cf",
    "yhn123qazxc.gq", "mju456wsxed.xyz", "nhy789bgtfr.top", "bgf456cdxsw.host",
    "zwq890vmjkl.party", "xdr123tfcvg.space", "plm456qazws.site",
    "okn789edcij.press", "ijb456uhbgn.online", "uhb789ygvfc.website",
    "ygv456tfcdx.tech", "tf789rdxse.live", "rdx456eszwa.stream",
    "esz789qawsx.download", "waq456zsxed.xyz", "dcr789fvbtg.work",
    "gbt456nhyuj.date", "mju789iklop.bid", "qwe456rtyui.trade",
    "uio789pasdf.ga", "asd456fghjk.ml", "zxc789vbnmq.cf", "rty456uiopp.gq",
    "fgh789jklzx.xyz", "vbn456mnbvc.top", "lkj456qwert.host",
    "poi789mnbvc.party", "mnb456lkjhg.space", "bec789wyxbw.site",
    "yvk456qjzzd.press", "hxz789vcjec.online", "tdt456knhko.website",
    "owu789pdkbg.tech", "gqs456ewqky.live", "cpv789jkcpj.stream",
    "knd456ncpum.download", "pzo789mhwnz.work", "a3b8c1d7.info",
    "e2f9g4h6.mobi", "i5j0k3l8.name", "m7n2o9p4.pro", "q1r6s3t8.loan",
    "u7v2w9x4.win", "y1z6a3b8.crypt", "c5d2e7f9.host", "g4h1i6j8.press",
    "k9l3m2n7.site", "o6p1q4r8.space", "s7t2u9v5.website", "w3x8y1z6.online",
    "a5b9c2d4.xyz", "e1f6g3h8.top", "i7j2k5l9.live", "m4n8o1p6.stream",
    "q9r3s7t2.download", "u5v1w6x8.review",
]

_FEATURE_ORDER = [
    "domain_length", "subdomain_count", "digit_ratio", "consonant_ratio",
    "vowel_ratio", "bigram_entropy", "trigram_entropy",
    "longest_word_length", "tld_risk_score",
]


def _features_to_vector(features: Dict[str, float]) -> List[float]:
    return [features[k] for k in _FEATURE_ORDER]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class DGAClassifier(BaseAnomalyDetector):
    """Supervised DGA domain classifier using RandomForest.

    Trained on 200 hardcoded labeled domains (100 known-good, 100 DGA).
    Classifies new domains in the Pi-hole event pipeline and flags those
    with DGA probability > 0.95.
    """

    def __init__(self):
        self._model = None
        self._trained = False
        self._last_results: List[AnomalyResult] = []
        self._last_run: Optional[datetime] = None
        self._train()

    # ------------------------------------------------------------------
    # BaseAnomalyDetector abstract property implementations
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "dga_classifier"

    @property
    def description(self) -> str:
        return "Supervised RandomForest DGA domain classifier"

    @property
    def last_results(self) -> List[AnomalyResult]:
        return self._last_results

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def _train(self, analyst_labels: Optional[List[dict]] = None):
        """Train the RandomForest classifier on hardcoded + analyst-labeled data."""
        X = []
        y = []
        analyst_domains = set()

        if analyst_labels:
            for row in analyst_labels:
                d = row["domain"]
                analyst_domains.add(d.lower().rstrip("."))
                features = extract_features(d)
                X.append(_features_to_vector(features))
                y.append(row["label"])

        for domain in KNOWN_GOOD_DOMAINS:
            if domain.lower() not in analyst_domains:
                features = extract_features(domain)
                X.append(_features_to_vector(features))
                y.append(0)

        for domain in DGA_DOMAINS:
            if domain.lower() not in analyst_domains:
                features = extract_features(domain)
                X.append(_features_to_vector(features))
                y.append(1)

        n_analyst = len(analyst_domains)
        n_legit = sum(1 for label in y if label == 0)
        n_dga = sum(1 for label in y if label == 1)

        try:
            from sklearn.ensemble import RandomForestClassifier
            self._model = RandomForestClassifier(
                n_estimators=50,
                max_depth=8,
                random_state=42,
                n_jobs=-1,
            )
            self._model.fit(X, y)
            self._trained = True
            logger.info("DGA classifier trained", extra={
                "extra_data": {
                    "samples": len(X),
                    "analyst_labels": n_analyst,
                    "legitimate": n_legit,
                    "dga": n_dga,
                }
            })
        except Exception as e:
            logger.warning("Failed to train RandomForest, using heuristic fallback", extra={
                "extra_data": {"error": str(e)}
            })
            self._trained = False

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict_proba(self, domain: str) -> Tuple[float, float]:
        """Return (legitimate_probability, dga_probability) for a domain.

        Falls back to heuristic scoring if sklearn is unavailable.
        """
        features = extract_features(domain)
        vec = _features_to_vector(features)

        if self._trained and self._model is not None:
            try:
                proba = self._model.predict_proba([vec])[0]
                if len(proba) == 2:
                    return float(proba[0]), float(proba[1])
                return float(proba[0]), 0.0
            except Exception:
                pass

        # Heuristic fallback
        from ueba.analytics.detectors import shannon_entropy, _dga_score
        name = domain.rsplit(".", 1)[0] if "." in domain else domain
        if len(name) < 8:
            return 0.98, 0.02
        dga = _dga_score(name)
        entropy = shannon_entropy(name)
        # Combine multiple weak signals
        score = 0.0
        if features["digit_ratio"] > 0.15:
            score += 0.3
        if features["vowel_ratio"] < 0.25:
            score += 0.25
        if features["consonant_ratio"] > 0.70:
            score += 0.2
        if features["domain_length"] > 20:
            score += 0.15
        if features["tld_risk_score"] > 0.5:
            score += 0.1
        score = min(score + dga * 0.2, 0.99)
        return 1.0 - score, score

    # ------------------------------------------------------------------
    # Per-query analysis
    # ------------------------------------------------------------------

    def analyze_query(
        self,
        client_ip: str,
        domain: str,
        query_type: str = "A",
        blocked: bool = False,
        timestamp: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Analyze a single Pi-hole DNS query for DGA patterns.

        Returns a list of behavioral flag dicts if DGA probability > 0.95.
        """
        if not domain:
            return []

        domain_lower = domain.lower().rstrip(".")
        if domain_lower.endswith(".in-addr.arpa") or domain_lower.endswith(".ip6.arpa"):
            return []

        _, dga_prob = self.predict_proba(domain)

        if dga_prob > 0.95:
            ts = timestamp or datetime.now(timezone.utc)
            features = extract_features(domain)
            logger.info("DGA classifier flagged domain", extra={
                "extra_data": {
                    "domain": domain,
                    "client_ip": client_ip,
                    "dga_probability": round(float(dga_prob), 4),
                }
            })
            return [{
                "flag_type": "dga_classifier",
                "details": {
                    "domain": domain,
                    "client_ip": client_ip,
                    "dga_probability": round(float(dga_prob), 4),
                    "features": features,
                    "query_type": query_type,
                    "blocked": blocked,
                },
                "timestamp": ts,
            }]
        return []

    # ------------------------------------------------------------------
    # Batch detection
    # ------------------------------------------------------------------

    async def detect(self) -> List[AnomalyResult]:
        """Batch detection — returns current results.

        The DGA classifier operates per-event; batch mode reports
        recent results.
        """
        self._last_run = datetime.now(timezone.utc)
        return self._last_results

    def get_stats(self) -> Dict[str, Any]:
        """Return current classifier statistics."""
        return {
            "trained": self._trained,
            "model_type": "RandomForest" if self._trained else "HeuristicFallback",
            "training_samples": len(KNOWN_GOOD_DOMAINS) + len(DGA_DOMAINS),
        }
