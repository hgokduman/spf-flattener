import dns.resolver
import CloudFlare
import os

SPF_CF_TOKEN = os.environ["SPF_CF_TOKEN"]
SPF_DOMAIN = os.environ["SPF_DOMAIN"]


def DNSRequest(host, type):
    try:
        answers = dns.resolver.resolve(host, type)
        for rdata in answers:
            if type == "TXT":
                yield rdata.to_text()[1:-1]
            else:
                yield rdata.to_text()
    except Exception as e:
        pass
    
def ParseSPF(host):
    try:
        for record in DNSRequest(host, "TXT"):
            fields = record.split(" ")
            if fields[0] != "v=spf1":
                continue
                
            parsed = [tuple(f.split(":",1)) if ":" in f else (f, None) for f in fields if ":" in f or f in ["mx", "ip4", "ip6"]]
            for tag,value in parsed:
                if tag == "include":
                    yield from ParseSPF(value)
                elif tag == "ip4":
                    yield (tag, value)
                elif tag == "ip6":
                    yield (tag, value)
                elif tag == "mx":
                    for x in DNSRequest(host, "MX"):
                        _, hostname = x.split(" ")
                        for ip in DNSRequest(hostname, "A"):
                            yield ("ip4", ip)
                        for ip in DNSRequest(hostname, "AAAA"):
                            yield ("ip6", ip)
    except Exception as e:
        print(e)



allowed_hosts = list(set([f"{k}:{v}" for k,v in ParseSPF(f"spf.{SPF_DOMAIN}")]))

dns_entries = [{"content": []}]
for host in allowed_hosts:
    if(len(" ".join(dns_entries[-1]["content"] + [host])) > 225):
        dns_entries.append({"content": [host]})
    else:
        dns_entries[-1]["content"].append(host)

for i,x in enumerate(dns_entries):
    dns_entries[i]["name"] = f"_spf.{SPF_DOMAIN}" if i == 0 else f"s{i}._spf.{SPF_DOMAIN}"
    dns_entries[i].update({"ttl": 60, "type": "TXT", "comment": "SPF Flattener"})
    dns_entries[i]["content"] = f"v=spf1 {' '.join(x['content'])}"
    if i < len(dns_entries)-1:
        dns_entries[i]["content"] += f" include:s{i+1}._spf.{SPF_DOMAIN}"


cf = CloudFlare.CloudFlare(token = SPF_CF_TOKEN)
zone_id = cf.zones.get(params={"name": SPF_DOMAIN})[0]["id"]
for dns_entry in cf.zones.dns_records.get(zone_id, params={"comment": "SPF Flattener"}):
    try:
        cf.zones.dns_records.delete(zone_id, dns_entry["id"])
        print(f"Deleted record {dns_entry['id']}")
    except:
        pass

for dns_entry in dns_entries:
    try:
        r = cf.zones.dns_records.post(zone_id,data=dns_entry)
        print(f"Created record {r['id']}")
    except:
        pass



