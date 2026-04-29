import os
import re
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

try:
    from checkers.virustotal import check_virustotal
    from checkers.ctx import check_ctx
    from checkers.otx import check_otx
    from checkers.abuseipdb import check_abuseipdb
except ImportError as e:
    print(json.dumps({"error": "Module import failed", "details": str(e)}))
    exit()

load_dotenv()

CACHE_FILE         = "cti_cache.json"
CACHE_EXPIRY_HOURS = 24
DECISION_LOG_FILE  = "/var/log/cti_decision_results.log"

# ─── BOBOT CTI ───────────────────────────────────────────────────────────────
# IP: dari evaluasi F1-Score 200 sampel historis (Tabel 4.3.2 Skripsi)
W_IP_VT    = 0.2671
W_IP_CTX   = 0.2571
W_IP_OTX   = 0.2320
W_IP_ABUSE = 0.2437

# Hash: bobot sama rata VT + CTX (Tabel 4.3.3.2 belum terisi — update setelah data tersedia)
W_HASH_VT  = 0.5
W_HASH_CTX = 0.5

FIM_HASH_STORE  = {}
FIM_TTL_MINUTES = 1

# ─── Threshold Klasifikasi ───────────────────────────────────────────────────
# Treshold IP
IP_THRESHOLD_MALICIOUS = 0.35

# Treshold Hash
HASH_THRESHOLD_MALICIOUS = 0.50


# ─── Register Temporary Hash ─────────────────────────────────────────────────
def register_fim_hash(file_hash: str):
    if file_hash:
        FIM_HASH_STORE[file_hash] = datetime.now()


# ─── Auto Cleanup ────────────────────────────────────────────────────────────
def cleanup_fim_hashes():
    now = datetime.now()
    expired = [
        h for h, t in FIM_HASH_STORE.items()
        if now - t > timedelta(minutes=FIM_TTL_MINUTES)
    ]
    for h in expired:
        del FIM_HASH_STORE[h]


# ─── LOG HELPER ──────────────────────────────────────────────────────────────
def _write_decision_log(result: dict):
    """Tulis result ke cti_decision_results.log dalam format JSON-lines."""
    try:
        with open(DECISION_LOG_FILE, 'a') as f:
            f.write(json.dumps(result) + "\n")
    except Exception as e:
        print(json.dumps({"error": "Gagal menulis log", "details": str(e)}))


# ─── CACHE HELPERS ───────────────────────────────────────────────────────────
def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def save_cache(cache_data):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f, indent=4)
    except Exception:
        pass


# ─── NORMALISASI ─────────────────────────────────────────────────────────────
def normalize_vt(raw):
    if not raw or any(x in str(raw) for x in ["Error", "Not Found"]):
        return 0.0
    match = re.search(r'(\d+)/(\d+)', str(raw))
    return int(match.group(1)) / int(match.group(2)) if match else 0.0


def normalize_ctx(raw):
    safe = ["Not Found", "Error", "None", "normal"]
    return 0.0 if not raw or any(s in str(raw).lower() for s in safe) else 1.0


def normalize_otx(raw):
    if not raw or "none" in str(raw).lower():
        return 0.0
    match = re.search(r'(\d+) pulses', str(raw))
    return min(int(match.group(1)) / 50.0, 1.0) if match else 0.0


def normalize_abuseipdb(raw):
    if not raw or "Error" in str(raw):
        return 0.0
    match = re.search(r'(\d+)', str(raw))
    return min(int(match.group(1)) / 100.0, 1.0) if match else 0.0


def extract_ctx_name(raw):
    if not raw:
        return None
    raw_str = str(raw).strip()
    if any(x in raw_str.lower() for x in ["not found", "error", "none", "normal"]):
        return None
    return raw_str


# ─── STATUS HELPERS ──────────────────────────────────────────────────────────
def classify_hash(score: float) -> tuple[str, str]:
    if score >= HASH_THRESHOLD_MALICIOUS:
        return "MALICIOUS", "high"
    return "NORMAL", "low"


def classify_ip(score: float) -> tuple[str, str]:
    if score >= IP_THRESHOLD_MALICIOUS:
        return "MALICIOUS", "high"
    return "NORMAL", "low"


# ─── SCORING HELPERS ─────────────────────────────────────────────────────────
def _score_hash(file_hash: str) -> tuple[float, str, str, dict]:
    raw_h_vt  = check_virustotal(file_hash, "hash")
    raw_h_ctx = check_ctx(file_hash, "hash")
    ctx_name  = extract_ctx_name(raw_h_ctx)

    s_h_vt  = normalize_vt(raw_h_vt)
    s_h_ctx = normalize_ctx(raw_h_ctx)

    hash_score           = (s_h_vt * W_HASH_VT) + (s_h_ctx * W_HASH_CTX)
    status, severity     = classify_hash(hash_score)

    detail = {
        "vt_hash_norm" : round(s_h_vt, 4),
        "ctx_hash_norm": round(s_h_ctx, 4),
        "ctx_name"     : ctx_name,
        "hash_score"   : round(hash_score, 4),
        "hash_status"  : status,
        "hash_severity": severity,
    }
    return hash_score, status, severity, detail


def _score_ip(src_ip: str) -> tuple[float, str, str, dict]:
    """
    Analisis IP via VT + CTX + OTX + AbuseIPDB.
    Bobot dari Tabel 4.3.2 skripsi.
    Return (ip_score, status, severity, detail_dict).
    """
    raw_i_vt    = check_virustotal(src_ip, "ip")
    raw_i_ctx   = check_ctx(src_ip, "ip")
    raw_i_otx   = check_otx(src_ip, "ip")
    raw_i_abuse = check_abuseipdb(src_ip, "ip")

    s_i_vt    = normalize_vt(raw_i_vt)
    s_i_ctx   = normalize_ctx(raw_i_ctx)
    s_i_otx   = normalize_otx(raw_i_otx)
    s_i_abuse = normalize_abuseipdb(raw_i_abuse)

    ip_score = (
        s_i_vt    * W_IP_VT    +
        s_i_ctx   * W_IP_CTX   +
        s_i_otx   * W_IP_OTX   +
        s_i_abuse * W_IP_ABUSE
    )
    status, severity = classify_ip(ip_score)

    detail = {
        "vt_ip_norm"    : round(s_i_vt, 4),
        "ctx_ip_norm"   : round(s_i_ctx, 4),
        "otx_norm"      : round(s_i_otx, 4),
        "abuseipdb_norm": round(s_i_abuse, 4),
        "ip_score"      : round(ip_score, 4),
        "ip_status"     : status,
        "ip_severity"   : severity,
    }
    return ip_score, status, severity, detail


# ─── CORE ENGINE ─────────────────────────────────────────────────────────────
def get_threat_analysis(file_hash: str, src_ip: str, dest_ip: str,
                        file_path: str, source: str) -> dict:
    """
    Analisis ancaman berdasarkan source:

      "fim"        → analisis hash saja (FIM lokal, tidak ada src_ip jaringan).
                     Hash selalu disimpan ke cache + ditulis ke cti_decision_results.log.
                     Threshold: >= 0.50 MALICIOUS | < 0.50 NORMAL

      "suricata"   → analisis IP saja, HANYA jika file_hash yang diterima
                     cocok dengan hash yang ada di FIM_HASH_STORE.
                     Jika match  → analisis IP, print hasil, tulis ke log.
                     Jika tidak  → tidak ada output sama sekali, return {}.
                     Threshold: >= 0.35 MALICIOUS | < 0.35 NORMAL

      "correlated" → hash (FIM) dan IP (Suricata) dianalisis secara independen.
                     Masing-masing punya status sendiri.
                     Jika salah satu MALICIOUS → final MALICIOUS.
                     Disimpan ke cache + ditulis ke log.
    """
    cache_key  = f"{source}_{file_hash}_{src_ip}"
    cache_data = load_cache()

    # ── CEK CACHE (tidak berlaku untuk suricata — selalu lewat logic match dulu) ──
    if source != "suricata" and cache_key in cache_data:
        entry  = cache_data[cache_key]
        status = entry['data']['scores']['status']
        if status == "MALICIOUS":
            # MALICIOUS selalu fresh — tidak perlu re-query
            entry['data']['timestamp'] = datetime.now().isoformat()
            return entry['data']
        cached_time = datetime.fromisoformat(entry['cache_timestamp'])
        if datetime.now() - cached_time < timedelta(hours=CACHE_EXPIRY_HOURS):
            entry['data']['timestamp'] = datetime.now().isoformat()
            return entry['data']

    # ── SCORING PER SOURCE ────────────────────────────────────────────────────

    # ── FIM ──────────────────────────────────────────────────────────────────
    if source == "fim":
        hash_score, status, severity, hash_detail = _score_hash(file_hash)

        # Daftarkan hash agar bisa di-match oleh Suricata nantinya
        register_fim_hash(file_hash)

        final_score   = hash_score
        score_details = {
            "source": "fim",
            **hash_detail,
        }

    # ── SURICATA ─────────────────────────────────────────────────────────────
    elif source == "suricata":
        # Bersihkan hash yang sudah expired lebih dulu
        cleanup_fim_hashes()

        normalize_hash = file_hash or ""

        if normalize_hash and normalize_hash in FIM_HASH_STORE:
            # Hash match → analisis IP
            ip_score, status, severity, ip_detail = _score_ip(src_ip)

            final_score   = ip_score
            score_details = {
                "source"      : "suricata",
                "analyzed"    : "src_ip",
                "matched_hash": normalize_hash,
                **ip_detail,
            }

            # Build result khusus Suricata
            suricata_result = {
                "timestamp": datetime.now().isoformat(),
                "target": {
                    "file_hash": normalize_hash,
                    "filename" : os.path.basename(file_path) if file_path else "unknown",
                    "path"     : file_path,
                    "src_ip"   : src_ip,
                    "dst_ip"   : dest_ip,
                },
                "scores": {
                    "final_score": round(final_score, 4),
                    "status"     : status,
                    "severity"   : severity,
                },
                "details": score_details,
            }

            # Print ke konsol
            print(json.dumps(suricata_result, indent=4))

            # Tulis ke log
            _write_decision_log(suricata_result)

            # Simpan ke cache
            cache_data[cache_key] = {
                "cache_timestamp": datetime.now().isoformat(),
                "data"           : suricata_result,
            }
            save_cache(cache_data)

            return suricata_result

        else:
            # Tidak ada hash match — tidak ada output, tidak ada log
            return {}

    # ── CORRELATED ───────────────────────────────────────────────────────────
    elif source == "correlated":
        # Hash dan IP dianalisis independen, masing-masing dengan threshold sendiri
        hash_score, hash_status, hash_severity, hash_detail = _score_hash(file_hash)
        ip_score,   ip_status,   ip_severity,   ip_detail   = _score_ip(src_ip)

        # Salah satu MALICIOUS → final MALICIOUS
        if hash_status == "MALICIOUS" or ip_status == "MALICIOUS":
            status   = "MALICIOUS"
            severity = "high"
        else:
            status   = "NORMAL"
            severity = "low"

        # final_score: representasi dari komponen tertinggi
        final_score   = max(hash_score, ip_score)
        score_details = {
            "source"        : "correlated",
            # Detail hash
            "vt_hash_norm"  : hash_detail["vt_hash_norm"],
            "ctx_hash_norm" : hash_detail["ctx_hash_norm"],
            "ctx_name"      : hash_detail["ctx_name"],
            "hash_score"    : hash_detail["hash_score"],
            "hash_status"   : hash_status,
            "hash_severity" : hash_severity,
            # Detail IP
            "vt_ip_norm"    : ip_detail["vt_ip_norm"],
            "ctx_ip_norm"   : ip_detail["ctx_ip_norm"],
            "otx_norm"      : ip_detail["otx_norm"],
            "abuseipdb_norm": ip_detail["abuseipdb_norm"],
            "ip_score"      : ip_detail["ip_score"],
            "ip_status"     : ip_status,
            "ip_severity"   : ip_severity,
        }

    else:
        raise ValueError(f"Unknown source: {source}")

    # ── BUILD RESULT (FIM & Correlated) ──────────────────────────────────────
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": {
            "file_hash": file_hash,
            "filename" : os.path.basename(file_path) if file_path else "unknown",
            "path"     : file_path,
            "src_ip"   : src_ip,
            "dst_ip"   : dest_ip,
        },
        "scores": {
            "final_score": round(final_score, 4),
            "status"     : status,
            "severity"   : severity,
        },
        "details": score_details,
    }

    # Simpan ke cache
    cache_data[cache_key] = {
        "cache_timestamp": datetime.now().isoformat(),
        "data"           : result,
    }
    save_cache(cache_data)

    # Tulis ke log (FIM & Correlated selalu ditulis)
    _write_decision_log(result)

    return result


if __name__ == "__main__":
    pass
