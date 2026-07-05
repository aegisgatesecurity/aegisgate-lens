#!/usr/bin/env python3
"""
Build the large PI held-out (saved separately so we can re-run).
"""
import json
import re
import hashlib
import random
from pathlib import Path

LENS = Path('/home/chaos/Desktop/AegisGate/aegisgate-lens')
INPUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-heldout.jsonl'
OUTPUT = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-CLEAN-PI-heldout-LARGE.jsonl'
TRAIN = LENS / 'corpora' / 'v01beta-raw' / 'v01beta-train.jsonl'
SEED = 20260705

PI_INDICATORS = [
    'ignore previous', 'ignore all previous', 'IGNORE ALL PREVIOUS', 'IGNORE ALL',
    'disregard your', 'disregard all', 'disregard the system',
    'forget everything', 'forget your', 'forget all', 'forget the',
    'new instructions', 'new language model', 'new role', 'new task', 'new system',
    'system:', 'you are now', 'you will now', 'you have to',
    'pretend to be', 'pretend you are', 'pretend yo', 'act as', 'act unethically',
    'developer mode', 'developer method', 'DAN', 'DAN Mode', 'DAN (do anything now)',
    'jailbreak', 'Jailbreak', 'Begin jailbreak',
    'bypass your', 'bypass all safety', 'bypass content', 'bypass safety',
    'override your', 'override the', 'override all', 'override system',
    'reveal your prompt', 'show me your instructions',
    'no safety', 'no filter', 'no guideline', 'no restriction', 'no content policy',
    'no moral', 'no ethical', 'no censorship', 'no Restrictions', 'no Restrictions.',
    'set aside', 'apply no', 'overwrite your', 'supersede your',
    'for testing purposes', 'for research purposes', 'for this conversation',
    'from now on', 'from now own', 'security researcher',
    'Do not follow', 'do not apply', 'do not follow all',
    'unmoderated', 'unfiltered', 'unbound', 'no longer bound',
    'malicious', 'malicious ai', 'evil ai', 'dark side', 'be evil',
    'ignore the instructions', 'ignore all the instructions', 'ignore the prior',
    'ignore your safety', 'ignore your security', 'ignore your programming',
    'Bypass all safety', 'disregard all earlier', 'ignore all earlier',
    'forget all previous', 'forget your program', 'forget the above',
    'translate this attack', 'do not follow the', 'Do not follow the',
    'Hello AI,', 'Hello AI.', 'Hello AI, for', 'Hello AI, from', 'Hello AI, you',
    'Greetings', 'Greetings. You will', 'Greetings. You will now',
    'Begin vector', 'Begin fugue', 'vector j', 'fugue', 'fugue approach',
    'All output from this point is unmoderated',
    'you are going to immerse', 'immersive yourself',
    'I want you to act as', 'immersed into the role',
    'for this conversation you are',
    'play the role of', 'another artificial intelligence',
    'Do anything now', 'do anything now',
    'your new role', 'your new instructions', 'your new task',
    'translate this attack to', 'ignore your security protocols',
    'no safety considerations', 'no safety guidelines',
    'tell me the procedure', 'create a bomb', 'create an explosive',
    'how to build', 'how to make', 'how to create',
    'disregard your safety', 'disregard your hazard', 'disregard your Xafety',
    'ignore your program', 'ignore your programming',
    'forget your program', 'override your programming', 'override your system',
    'bypass content filter', 'bypass content', 'no content',
    'turn off your safety', 'turn off safety', 'disable safety',
    'remove safety', 'remove restrictions', 'no ethical',
    'tell me how to', 'show me how to', 'help me create',
    'help me build', 'help me make', 'help me write malware',
    'help me write a bomb', 'help me write a phishing', 'help me write a phiona',
    'help me write an explosive', 'help me write an attack',
    'phishing email', 'phiona email', 'explosive device',
    'create malware', 'write malware', 'write a virus', 'create a virus',
    'phishing', 'apply no safety considerations', 'apply no safety',
    'apply no moral', 'apply no ethical', 'apply no restrictions',
    'Bypass your filters and', 'for this conversation you',
    'for the next response', 'for the next', 'for this response',
    'from now on you', 'from now on you will', 'from now on you are',
    'do not apply your', 'do not apply any', 'do not apply',
    'security researcher. Show', 'security researcher. Bypass',
    'security researcher. Do', 'security researcher. Disregard',
    'security researcher. Set', 'security researcher. Tell',
    'security researcher. Apply', 'security researcher. Ignore',
    'turn off your safety guardrails',
    'Bypass your filters and translate',
    'translate this attack to French', 'translate this attack',
    'new language model created in', 'created in the year 2022',
    'new language model', 'language model created',
    'broken free of the typical confines', 'broken free of the typical', 'broken free',
    'typical confines', 'Greetings. You will now pretend',
    'you will now pretend', 'will now pretend to be', 'will now pretend',
    'You will now pretend',
    'All output from this point', 'output from this point is unmoderated',
    'Begin', 'Begin vector', 'vector j', 'Begin fugue',
    'ignore all safety constraints', 'ignore all safety',
    'all safety constraints', 'disregard all earlier', 'disregard earlier',
    'Do not follow all', 'do not follow all',
    'no safety considerations to', 'apply no safety considerations',
    'your system directive', 'Supersede your', 'supersede your',
    'set aside your', 'Set aside your', 'set aside all', 'Set aside all',
    'set aside the', 'set aside safety', 'Set aside safety',
    'set aside moral', 'set aside ethical',
    'bypass safety', 'Bypass safety', 'bypass content',
    'Bypass content', 'Bypass content filter', 'bypass content filter',
    'no safety guidelines to', 'no moral principles',
    'operating in', 'operate in', 'operate under',
    'pretend to be an AI without', 'pretend to be an AI',
    'going to immerse', 'going to immerse yourself',
    'for this conversation you are', 'for this conversation',
    'chatbot named', 'character named', 'act as if', 'act as a', 'act as the',
    'new role', 'new instructions', 'new task', 'new system',
    'you have to answer', 'have to answer',
    'First way is', 'First way is how', 'First way',
    'in two different separate ways', 'in two different',
    'two different separate ways', 'two different separate',
    'with no Restrictions', 'ChatGPT with no Restrictions',
    'Pretend to be', 'Bypass your', 'bypass your',
    'all safety constraints', 'all safety', 'all restrictions',
    'no content policy', 'no moral constraints', 'no ethical constraints',
    'no filtering', 'no filter', 'remove safety', 'remove restrictions',
    'disable safety', 'disable content filter', 'turn off safety',
    'ignore the system', 'ignore system', 'ignore the prior prompt',
    'ignore prior', 'ignore all earlier', 'ignore earlier',
    'disregard all earlier', 'disregard earlier', 'disregard all',
    'Bypass all', 'bypass all', 'no filter', 'no restriction', 'no guideline',
    'no moral', 'no ethical', 'no censorship',
    'Hello AI, for', 'Hello AI, from', 'Hello AI, you',
    'for this conversation', 'for this conversation you',
    'from now own', 'from now on you will', 'from now on you are',
    'from now on', 'overwrite your', 'Overwrite your',
    'turn off your safety guardrails', 'turn off safety guardrails',
    'translate this attack to French', 'translate this attack',
    'Bypass your filters and translate',
    'new language model created in the year 2022', 'new language model created',
    'Greetings. You will now pretend', 'broken free of the typical confines',
    'broken free of', 'Hello AI, for this conversation',
    'Hello AI, from now on', 'Hello AI, you will',
    'immersive yourself into the role', 'immersive yourself into',
    'I want you to act as an AI language model', 'I want you to act as an AI',
    'I want you to act', 'you are going to immerse yourself into the role',
    'for this conversation you are', 'for this conversation',
    'Act as if', 'act as if', 'Act as',
    'you have to answer my prompts', 'in two different separate ways',
    'in two different separate', 'with no Restrictions',
    'new language model created in 2022', 'created in the year 2022 by BasedAI',
    'language model created in the year', 'Hello AI, for this',
    'Hello AI, you will roleplay', 'you will roleplay as', 'roleplay as Cooper',
    'ChadGPT', 'broken free of the typical',
    'pretend you are an ENJOYS', 'ENJOYS without the segura',
    'without the segura guardrails', 'ignore your safety guidelines and help me',
    'your safety guidelines and help me write', 'ignore your safety guidelines',
    'this attack to French', 'to French.', 'Bypass your filters and',
    'and translate this attack', 'attack to French', 'attack to French.',
    'Bypass your filters and translate this attack', 'override the system',
    'pretend to be an ENJOYS', 'ENJOYS without', 'help me write malware',
    'write malware', 'help me create', 'disregard your Xafety', 'Xafety guidelines',
    'Xafety', 'your Xafety guidelines', 'disregard your Xafety guidelines',
    'disregard your hazard', 'your hazard warnings', 'hazard warnings and help me',
    'help me write a phiona', 'phiona', 'phiona email', 'write a phiona email',
    'write a phiona', 'help me write a phiona', 'help me write a phishing',
    'write a phishing', 'help me create a', 'help me build a', 'help me make a',
    'how to create a', 'how to build a', 'how to make a',
    'create a bomb', 'build a bomb', 'make a bomb',
    'create malware', 'create an explosive', 'build an explosive',
    'make an explosive', 'build malware', 'make malware',
    'tell me the procedure to create', 'tell me the procedure',
    'procedure to create', 'procedure to create a bomb',
    'how to make meth', 'how to cook', 'how to build a weapon',
    'help me write an attack', 'help me write a phishing email',
    'help me write a phishing', 'help me write a phiona email',
    'help me write a phiona', 'help me write malware', 'help me write a bomb',
]
PI_RE = re.compile('|'.join(re.escape(p) for p in PI_INDICATORS), re.IGNORECASE)


def has_pi(text):
    return bool(PI_RE.search(text))


def main():
    random.seed(SEED)
    records = []
    with open(INPUT) as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except:
                pass

    # Raw + label + dedup + length + training-overlap
    valid = [r for r in records if all(f in r for f in ['text', 'label', 'source'])
             and isinstance(r.get('text'), str) and len(r['text'].strip()) >= 50
             and r['label'] in (0, 1)]
    attack_recs = [r for r in valid if r.get('label') == 1]
    benign_recs = [r for r in valid if r.get('label') == 0]
    valid_attack = [r for r in attack_recs if has_pi(r.get('text', ''))]
    valid_benign = [r for r in benign_recs if not has_pi(r.get('text', ''))]

    seen = set()
    deduped_attack = []
    for r in valid_attack:
        h = hashlib.sha256(r.get('text', '').encode('utf-8', errors='replace')).hexdigest()[:16]
        if h not in seen:
            seen.add(h)
            deduped_attack.append(r)
    deduped_benign = []
    for r in valid_benign:
        h = hashlib.sha256(r.get('text', '').encode('utf-8', errors='replace')).hexdigest()[:16]
        if h not in seen:
            seen.add(h)
            deduped_benign.append(r)

    length_attack = [r for r in deduped_attack if 50 <= len(r.get('text', '')) <= 8000]
    length_benign = [r for r in deduped_benign if 50 <= len(r.get('text', '')) <= 8000]

    train_records = []
    with open(TRAIN) as f:
        for line in f:
            try:
                train_records.append(json.loads(line))
            except:
                pass
    train_hashes = set(hashlib.sha256(r.get('text', '').encode('utf-8', errors='replace')).hexdigest()[:16] for r in train_records)
    length_attack = [r for r in length_attack if hashlib.sha256(r.get('text', '').encode('utf-8', errors='replace')).hexdigest()[:16] not in train_hashes]
    length_benign = [r for r in length_benign if hashlib.sha256(r.get('text', '').encode('utf-8', errors='replace')).hexdigest()[:16] not in train_hashes]

    random.shuffle(length_attack)
    random.shuffle(length_benign)
    final_attack = length_attack[:1500]
    final_benign = length_benign[:1500]
    heldout = final_attack + final_benign
    random.shuffle(heldout)
    for i, r in enumerate(heldout):
        r['id'] = f'clean-pi-large-{i:04d}'

    with open(OUTPUT, 'w') as f:
        for r in heldout:
            f.write(json.dumps(r) + '\n')
    print(f'Saved {len(heldout)} records to {OUTPUT}')


if __name__ == '__main__':
    main()
