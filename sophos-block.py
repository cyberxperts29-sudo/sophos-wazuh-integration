#!/usr/bin/env python3
# Wazuh Active Response: auto-block attacker IPs on Sophos Firewall via XML API
# Author: Muhammad Ahmad Abid
#
# Install:  /var/ossec/active-response/bin/sophos-block.py  (root:wazuh, 750)
# Config:   /var/ossec/etc/sophos_api.conf                   (root:wazuh, 640)
import sys, json, ssl, ipaddress, datetime, urllib.request, urllib.parse
from xml.sax.saxutils import escape

CONF = "/var/ossec/etc/sophos_api.conf"
LOG = "/var/ossec/logs/active-responses.log"


def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{datetime.datetime.now():%Y/%m/%d %H:%M:%S} sophos-block: {msg}\n")


def load_conf():
    conf = {}
    with open(CONF) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip()
    return conf


def sophos_api(conf, body):
    xml = (f"<Request><Login><Username>{escape(conf['username'])}</Username>"
           f"<Password>{escape(conf['password'])}</Password></Login>{body}</Request>")
    data = urllib.parse.urlencode({"reqxml": xml}).encode()
    ctx = ssl.create_default_context()
    if conf.get("verify_tls", "no").lower() != "yes":
        # Lab default: Sophos ships a self-signed certificate.
        # In production install a trusted certificate and set verify_tls=yes.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    url = f"https://{conf['host']}:{conf.get('port', '4444')}/webconsole/APIController"
    with urllib.request.urlopen(url, data=data, context=ctx, timeout=15) as r:
        return r.read().decode()


def main():
    msg = json.loads(sys.stdin.readline())
    if msg.get("command") != "add":
        return
    alert = msg["parameters"]["alert"]
    srcip = alert.get("data", {}).get("srcip")
    rule = alert.get("rule", {})
    if not srcip:
        log("no srcip in alert, skipping")
        return

    # Wazuh handshake: avoid processing the same IP twice in parallel
    print(json.dumps({"version": 1,
                      "origin": {"name": "sophos-block", "module": "active-response"},
                      "command": "check_keys", "parameters": {"keys": [srcip]}}))
    sys.stdout.flush()
    if json.loads(sys.stdin.readline()).get("command") != "continue":
        log(f"{srcip} already being handled, skipping")
        return

    conf = load_conf()
    whitelist = [w.strip() for w in conf.get("whitelist", "").split(",") if w.strip()]
    if ipaddress.ip_address(srcip).is_private or srcip in whitelist:
        log(f"{srcip} is private/whitelisted, not blocking")
        return

    group = escape(conf.get("group", "Wazuh-Blocked-IPs"))
    body = (f'<Set operation="add"><IPHost><Name>WZ-BLK-{srcip}</Name>'
            f'<IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>{srcip}</IPAddress>'
            f'<HostGroupList><HostGroup>{group}</HostGroup></HostGroupList></IPHost></Set>')
    try:
        out = sophos_api(conf, body)
        # Host already exists (e.g. from an earlier attempt): update it into the block group
        if 'code="502"' in out:
            out = sophos_api(conf, body.replace('operation="add"', 'operation="update"'))
    except Exception as e:
        log(f"API error for {srcip}: {e}")
        return

    if 'code="200"' in out:
        log(f"BLOCKED {srcip} on Sophos (rule {rule.get('id')}: {rule.get('description')})")
    else:
        log(f"Sophos did not confirm block for {srcip}: {' '.join(out.split())[:300]}")


if __name__ == "__main__":
    main()
