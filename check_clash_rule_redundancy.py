import os
import re
import ipaddress
from collections import defaultdict

RULES_DIR = 'Rules'
RULE_TYPES = [
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD',
    'PROCESS-NAME', 'USER-AGENT', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN',
    'URL-REGEX', 'SRC-IP-CIDR', 'SRC-PORT', 'DST-PORT'
]

# 解析规则行
rule_pattern = re.compile(r'^(#|$)|^([A-Z\-]+),(.+)$')

def parse_rule(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    m = rule_pattern.match(line)
    if not m:
        return None
    rule_type = m.group(2)
    value = m.group(3)
    if rule_type not in RULE_TYPES:
        return None
    return rule_type, value

# 递归读取所有规则文件
def load_all_rules():
    rules = defaultdict(list)
    for fname in os.listdir(RULES_DIR):
        if fname.endswith('.list'):
            with open(os.path.join(RULES_DIR, fname), encoding='utf-8') as f:
                for idx, line in enumerate(f, 1):
                    parsed = parse_rule(line)
                    if parsed:
                        rule_type, value = parsed
                        rules[rule_type].append({'value': value, 'file': fname, 'line': idx, 'raw': line.strip()})
    return rules

def domain_covered_by_keyword(domain, keywords):
    for kw in keywords:
        if kw in domain:
            return kw
    return None

def domain_covered_by_suffix(domain, suffixes):
    for suf in suffixes:
        if domain.endswith('.' + suf) or domain == suf:
            return suf
    return None

def suffix_covered_by_keyword(suffix, keywords):
    for kw in keywords:
        if kw in suffix:
            return kw
    return None

def ip_covered_by_cidr(ip, cidrs):
    ip_obj = ipaddress.ip_address(ip)
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        if ip_obj in net:
            return cidr
    return None

def cidr_covered_by_bigger_cidr(cidr, cidrs):
    net = ipaddress.ip_network(cidr, strict=False)
    for other in cidrs:
        if other == cidr:
            continue
        other_net = ipaddress.ip_network(other, strict=False)
        if net.subnet_of(other_net):
            return other
    return None

def check_redundancy(rules):
    redundant = []
    # DOMAIN
    domain_keywords = [r['value'] for r in rules['DOMAIN-KEYWORD']]
    domain_suffixes = [r['value'] for r in rules['DOMAIN-SUFFIX']]
    domains = [r['value'] for r in rules['DOMAIN']]
    # DOMAIN 被 DOMAIN-KEYWORD 覆盖
    for r in rules['DOMAIN']:
        kw = domain_covered_by_keyword(r['value'], domain_keywords)
        if kw:
            redundant.append((r, f'DOMAIN-KEYWORD,{kw}'))
            continue
        suf = domain_covered_by_suffix(r['value'], domain_suffixes)
        if suf:
            redundant.append((r, f'DOMAIN-SUFFIX,{suf}'))
    # DOMAIN-SUFFIX 被 DOMAIN-KEYWORD 覆盖
    for r in rules['DOMAIN-SUFFIX']:
        kw = suffix_covered_by_keyword(r['value'], domain_keywords)
        if kw:
            redundant.append((r, f'DOMAIN-KEYWORD,{kw}'))
    # DOMAIN/DOMAIN-SUFFIX/DOMAIN-KEYWORD 完全重复
    for t in ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD']:
        seen = set()
        for r in rules[t]:
            if r['value'] in seen:
                redundant.append((r, f'{t},{r["value"]} (重复)'))
            seen.add(r['value'])
    # IP-CIDR
    cidrs = [r['value'].split(',')[0] for r in rules['IP-CIDR']]
    for r in rules['IP-CIDR']:
        cidr = r['value'].split(',')[0]
        bigger = cidr_covered_by_bigger_cidr(cidr, cidrs)
        if bigger:
            redundant.append((r, f'IP-CIDR,{bigger}'))
    # IP-CIDR6
    cidr6s = [r['value'].split(',')[0] for r in rules['IP-CIDR6']]
    for r in rules['IP-CIDR6']:
        cidr = r['value'].split(',')[0]
        bigger = cidr_covered_by_bigger_cidr(cidr, cidr6s)
        if bigger:
            redundant.append((r, f'IP-CIDR6,{bigger}'))
    # IP-ASN 完全重复
    seen = set()
    for r in rules['IP-ASN']:
        if r['value'] in seen:
            redundant.append((r, f'IP-ASN,{r["value"]} (重复)'))
        seen.add(r['value'])
    # PROCESS-NAME 完全重复
    seen = set()
    for r in rules['PROCESS-NAME']:
        if r['value'] in seen:
            redundant.append((r, f'PROCESS-NAME,{r["value"]} (重复)'))
        seen.add(r['value'])
    # USER-AGENT 完全重复
    seen = set()
    for r in rules['USER-AGENT']:
        if r['value'] in seen:
            redundant.append((r, f'USER-AGENT,{r["value"]} (重复)'))
        seen.add(r['value'])
    # URL-REGEX 完全重复
    seen = set()
    for r in rules['URL-REGEX']:
        if r['value'] in seen:
            redundant.append((r, f'URL-REGEX,{r["value"]} (重复)'))
        seen.add(r['value'])
    # 其他类型可扩展
    return redundant

def main():
    rules = load_all_rules()
    redundant = check_redundancy(rules)
    if not redundant:
        print('未发现冗余或被覆盖规则。')
        return
    print('发现以下冗余或被覆盖规则：')
    for r, cover in redundant:
        print(f'{r["file"]}:{r["line"]}: {r["raw"]}  <-- 被 {cover} 覆盖')

if __name__ == '__main__':
    main() 