import json


def load_config(path: str):
    try:
        with open(path) as fp:
            cfg = json.load(fp)
            cfg["sycope_host"] = cfg["sycope_host"].strip().rstrip("/")
            cfg["api_base"] = "/"+cfg["api_base"].strip().rstrip("/").lstrip("/")+"/"
            for key in ("anomaly_whitelist", "alert_whitelist", "anomaly_blacklist", "alert_blacklist"):
                lst = cfg.get(key)
                cfg[f"{key}_set"] = set(lst) if isinstance(lst, list) else set()
            return cfg
    except Exception:
        raise
