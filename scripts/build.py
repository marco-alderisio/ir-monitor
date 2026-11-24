#!/usr/bin/env python3
"""
Incident source collector (Python 3.9+, standard library only).

Collects cyber-incident signals from authoritative public sources, normalises them into one
record format and writes ./site/data/incidents.json + status.json for the static page.
Runs on GitHub Actions (or any scheduler); nothing runs on a server.

Signal types
  claim       ransomware / extortion leak-site claim (earliest public signal, unverified)
  attack      cyberattack reported in the press, curated by ransomware.live
  disclosure  regulatory disclosure (SEC Form 8-K Item 1.05 / cyber 8.01)
  news        press report (cybersecurity press, food-industry trade press, Google News)
  advisory    government CERT alert / advisory

Industry tagging, relevance and country grouping are left to the consuming application.

Environment variables (all optional)
  IR_OUT        output folder                          (default: site/data)
  IR_PREV       previous incidents.json to merge       (default: cache/incidents.json)
  IR_KEEP_DAYS  history kept                           (default: 1110, about 3 years)
  IR_UA         User-Agent; SEC EDGAR requires a contact e-mail in it
  RL_BASE       ransomware.live API base               (default: https://api.ransomware.live/v2)
  RL_HEADER     extra header for that API, "Name: value" (e.g. a personal api-pro token)
  IR_OFFLINE    comma-separated source keys to skip
"""
import datetime as dt, email.utils, hashlib, html, json, os, re, sys, time, urllib.parse, urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

OUT = os.environ.get('IR_OUT') or 'site/data'
PREV = os.environ.get('IR_PREV') or 'cache/incidents.json'
KEEP_DAYS = int(os.environ.get('IR_KEEP_DAYS') or '1110')   # ~3 years, for 12/24/36-month trends
UA = os.environ.get('IR_UA') or 'incident-collector/1.0 (contact: security@example.com)'
RL_BASE = (os.environ.get('RL_BASE') or 'https://api.ransomware.live/v2').rstrip('/')
RL_HEADER = os.environ.get('RL_HEADER', '')
OFFLINE = set(filter(None, os.environ.get('IR_OFFLINE', '').split(',')))
NOW = dt.datetime.now(dt.timezone.utc)

# ----------------------------------------------------------------------------------------------
# SOURCES — edit freely. kind: rss (RSS/Atom), gnews (Google News search), sec, rl, pt, tc
# cat: claims | attacks | regulatory | press | trade | aggregator | gov
# ----------------------------------------------------------------------------------------------
RSS = [
  # Cybersecurity press — incident reporting
  ('bleeping',  'BleepingComputer',      'press', 'en', 'https://www.bleepingcomputer.com/feed/'),
  ('record',    'The Record',            'press', 'en', 'https://therecord.media/feed'),
  ('secweek',   'SecurityWeek',          'press', 'en', 'https://www.securityweek.com/feed/'),
  ('thn',       'The Hacker News',       'press', 'en', 'https://feeds.feedburner.com/TheHackersNews'),
  ('darkread',  'Dark Reading',          'press', 'en', 'https://www.darkreading.com/rss.xml'),
  ('secaff',    'Security Affairs',      'press', 'en', 'https://securityaffairs.com/feed'),
  ('dbnet',     'DataBreaches.net',      'press', 'en', 'https://databreaches.net/feed/'),
  ('csdive',    'Cybersecurity Dive',    'press', 'en', 'https://www.cybersecuritydive.com/feeds/news/'),
  ('register',  'The Register',          'press', 'en', 'https://www.theregister.com/security/headlines.atom'),
  ('lemagit',   'LeMagIT',               'press', 'fr', 'https://www.lemagit.fr/rss/ContentSyndication.xml'),
  ('zataz',     'ZATAZ',                 'press', 'fr', 'https://www.zataz.com/feed/'),
  ('lmi',       'Le Monde Informatique', 'press', 'fr', 'https://www.lemondeinformatique.fr/flux-rss/thematique/securite/rss.xml'),
  ('cs360',     'Cybersecurity360',      'press', 'it', 'https://www.cybersecurity360.it/feed/'),
  ('heise',     'heise Security',        'press', 'de', 'https://www.heise.de/security/rss/news-atom.xml'),
  ('unaaldia',  'Una al día',            'press', 'es', 'https://unaaldia.hispasec.com/feed'),
  # Food & dairy trade press (incidents are often reported here first)
  ('fooddive',  'Food Dive',             'trade', 'en', 'https://www.fooddive.com/feeds/news/'),
  ('justfood',  'Just Food',             'trade', 'en', 'https://www.just-food.com/feed/'),
  ('dairyrep',  'DairyReporter',         'trade', 'en', 'https://www.dairyreporter.com/arc/outboundfeeds/rss/'),
  ('foodnav',   'FoodNavigator',         'trade', 'en', 'https://www.foodnavigator.com/arc/outboundfeeds/rss/'),
  # Government CERTs
  ('cisa',      'CISA advisories',       'gov',   'en', 'https://www.cisa.gov/cybersecurity-advisories/all.xml'),
  ('certfr',    'CERT-FR alertes',       'gov',   'fr', 'https://www.cert.ssi.gouv.fr/alerte/feed/'),
  ('certfr_a',  'CERT-FR actualité',     'gov',   'fr', 'https://www.cert.ssi.gouv.fr/actualite/feed/'),
  ('ncsc',      'NCSC UK',               'gov',   'en', 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml'),
]
# Google News searches: the fastest general aggregator. One query per language/edition.
GNEWS = [
  ('gn_en', 'en', 'US', '(cyberattack OR ransomware OR "cyber attack" OR hackers OR "data breach") (dairy OR cheese OR milk OR creamery OR yogurt OR "food company" OR "food manufacturer" OR "food producer" OR meat OR poultry OR brewery OR "agricultural cooperative")'),
  ('gn_uk', 'en', 'GB', '(cyberattack OR ransomware OR "cyber attack") (dairy OR "food firm" OR "food supplier" OR supermarket OR "food manufacturer")'),
  ('gn_au', 'en', 'AU', '(cyberattack OR ransomware OR "cyber attack") (dairy OR milk OR "food company" OR "food manufacturer")'),
  ('gn_fr', 'fr', 'FR', '(cyberattaque OR rançongiciel OR ransomware OR piratage) (laiterie OR fromagerie OR lait OR agroalimentaire OR "coopérative laitière" OR "groupe alimentaire")'),
  ('gn_it', 'it', 'IT', '("attacco informatico" OR ransomware OR "attacco hacker") (caseificio OR latte OR lattiero OR alimentare OR "industria alimentare")'),
  ('gn_es', 'es', 'ES', '(ciberataque OR ransomware OR hackeo) (láctea OR lácteos OR leche OR alimentaria OR "empresa de alimentos")'),
  ('gn_mx', 'es', 'MX', '(ciberataque OR ransomware OR hackeo) (lácteos OR leche OR alimentos)'),
  ('gn_br', 'pt', 'BR', '("ataque hacker" OR ransomware OR "ataque cibernético") (laticínios OR leite OR alimentos OR frigorífico)'),
  # site-restricted searches: trade titles and outlets whose own feeds block automated readers
  ('gn_trade_en', 'en', 'US', '(cyberattack OR ransomware OR "cyber attack" OR "data breach" OR hackers) (site:foodmanufacturing.com OR site:foodprocessing.com OR site:dairyreporter.com OR site:just-food.com OR site:foodnavigator.com OR site:foodnavigator-usa.com OR site:fooddive.com OR site:supermarketnews.com OR site:dairyherd.com OR site:dairyfoods.com)'),
  ('gn_trade_fr', 'fr', 'FR', '(cyberattaque OR rançongiciel OR ransomware OR piratage) (site:lsa-conso.fr OR site:processalimentaire.com OR site:rayon-boissons.com OR site:reussir.fr OR site:lafranceagricole.fr OR site:linfo-durable.fr OR site:agra.fr)'),
  ('gn_cybernews', 'en', 'US', '(ransomware OR breach OR cyberattack OR hackers) site:cybernews.com'),
  ('gn_indcyber', 'en', 'US', '(cyberattack OR ransomware OR breach OR hackers OR attack OR OT OR ICS) site:industrialcyber.co'),
  ('gn_rhc', 'it', 'IT', '(attacco OR ransomware OR "data breach" OR violazione) site:redhotcyber.com'),
  ('gn_de', 'de', 'DE', '(Cyberangriff OR Ransomware OR Hackerangriff) (Molkerei OR Käserei OR Lebensmittel OR Milch)'),
]
SEC_QUERIES = [('"Item 1.05"', {'1.05'}), ('"cybersecurity incident"', {'1.05', '8.01'})]

INCIDENT_RE = re.compile(r"ransom|cyber[\s-]?att?a(?:ck|que)|cyber[\s-]?incident|cyberangriff|hackerangriff|it-angriff|attacco (?:informatico|hacker)|ciberataque|ataque (?:hacker|cibern)|"
                         r"\bhack(?:ed|ers?|eo|ing)?\b|piratage|piraté|hacké|breach|data (?:leak|theft)|fuite de donn|violazione|brecha|vazamento|datenleck|extortion|extorsion|"
                         r"stolen data|intrusion|compromis|malware|wiper|ddos|outage|systems? (?:down|offline)|shut ?down|disrupt|incident", re.I)

def log(*a): print(*a, file=sys.stderr, flush=True)

def fetch(url, timeout=40, headers=None, tries=2):
    h = {'User-Agent': UA, 'Accept': '*/*'}
    h.update(headers or {})
    last = None
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                return r.read()
        except Exception as e:
            last = e
            time.sleep(2 + 3 * i)
    raise last

TAG_RE = re.compile(r'<[^>]+>')
def text(s):
    if s is None: return ''
    s = html.unescape(TAG_RE.sub(' ', str(s)))
    return re.sub(r'\s+', ' ', s).strip()

def iso(v):
    """Any date (ISO, RFC 822, epoch) -> ISO 8601 UTC string, or ''."""
    if not v: return ''
    if isinstance(v, (int, float)):
        return dt.datetime.fromtimestamp(v / (1000 if v > 1e11 else 1), dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    s = str(v).strip()
    try:
        d = email.utils.parsedate_to_datetime(s)
    except Exception:
        d = None
    if d is None:
        try:
            d = dt.datetime.fromisoformat(s.replace('Z', '+00:00').replace(' ', 'T', 1))
        except Exception:
            m = re.match(r'(\d{4}-\d{2}-\d{2})', s)
            if not m: return ''
            d = dt.datetime.fromisoformat(m.group(1))
    if d.tzinfo is None: d = d.replace(tzinfo=dt.timezone.utc)
    d = d.astimezone(dt.timezone.utc)
    if d > NOW + dt.timedelta(hours=6): d = NOW      # clamp bad future dates
    return d.strftime('%Y-%m-%dT%H:%M:%SZ')

def norm(s): return re.sub(r'[^a-z0-9]+', '', text(s).lower())
def hid(*parts): return hashlib.sha1('|'.join(parts).encode()).hexdigest()[:14]
def domain_of(s):
    s = (s or '').strip().lower()
    if not s or '.onion' in s: return ''
    s = re.sub(r'^[a-z]+://', '', s).split('/')[0].split(':')[0]
    s = re.sub(r'^www\d?\.', '', s)
    return s if re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', s) else ''
def safe_url(u):
    u = (u or '').strip()
    return u if u.startswith('https://') or (u.startswith('http://') and '.onion' not in u) else ''

def rec(**k):
    r = {'id': '', 'type': '', 't': '', 'title': '', 'victim': '', 'domain': '', 'country': '', 'sector': '', 'actor': '',
         'summary': '', 'url': '', 'src': '', 'lang': '', 'srcs': []}
    r.update({a: b for a, b in k.items() if b not in (None, '')})
    r['title'] = r['title'][:300]; r['summary'] = r['summary'][:600]
    r['country'] = (r['country'] or '').upper()[:2] if re.match(r'^[A-Za-z]{2}$', r['country'] or '') else ''
    return r

# ---------------------------------------------------------------- claims (leak sites)
def claim(victim, group, when, country='', sector='', website='', desc='', url='', src=''):
    victim = text(victim); group = text(group).lower()
    if not victim or not group: return None
    d = domain_of(website) or domain_of(victim)
    return rec(id='c' + hid(norm(victim), group), type='claim', t=iso(when), title=victim, victim=victim, domain=d,
               country=country, sector=text(sector).replace('Not Found', ''), actor=group, summary=text(desc)[:600],
               url=safe_url(url) or f'https://www.ransomware.live/group/{urllib.parse.quote(group)}', src=src)

def src_rl_victims():
    h = dict([RL_HEADER.split(':', 1)]) if ':' in RL_HEADER else {}
    data = json.loads(fetch(RL_BASE + '/recentvictims', headers={k.strip(): v.strip() for k, v in h.items()}))
    if isinstance(data, dict): data = data.get('victims') or data.get('data') or []
    out = []
    for x in data:
        u = x.get('url') or ''
        out.append(claim(x.get('post_title') or x.get('victim'), x.get('group_name') or x.get('group'),
                         x.get('discovered') or x.get('published'), x.get('country'), x.get('activity') or x.get('sector'),
                         x.get('website') or x.get('domain'), x.get('description'), u if 'ransomware.live' in u else '', 'rl'))
    return out

def src_rl_attacks():
    h = dict([RL_HEADER.split(':', 1)]) if ':' in RL_HEADER else {}
    data = json.loads(fetch(RL_BASE + '/recentcyberattacks', headers={k.strip(): v.strip() for k, v in h.items()}))
    if isinstance(data, dict): data = data.get('cyberattacks') or data.get('data') or []
    out = []
    for x in data:
        title = text(x.get('title') or x.get('victim') or '')
        if not title: continue
        url = safe_url(x.get('url') or x.get('link'))
        out.append(rec(id='a' + hid(norm(url or title)), type='attack', t=iso(x.get('date') or x.get('added') or x.get('published')),
                       title=title, victim=text(x.get('victim') or ''), domain=domain_of(x.get('domain') or ''),
                       country=x.get('country') or '', summary=text(x.get('summary') or x.get('description') or ''),
                       url=url, src='rl_att'))
    return out

def _pt_site(x):
    m = re.search(r"href='([^']+)'", x.get('post_title') or '')
    return m.group(1) if m else ''

def src_pt():   # privtools mirror of ransomware.live (fields wrapped in HTML), last 30 days, refreshed ~3x/day
    data = json.loads(fetch('https://raw.githubusercontent.com/privtools/ransomposts/main/assets/recent.json', timeout=90))
    return [claim(x.get('post_title'), x.get('group_name'), x.get('discovered'), x.get('country'), x.get('activity'), _pt_site(x), '', '', 'pt') for x in data]

def src_pt_full():   # one-off history bootstrap when no previous data exists (~45 MB)
    lf = os.environ.get('IR_PT_FULL_FILE')
    data = json.load(open(lf)) if lf else json.loads(fetch('https://raw.githubusercontent.com/privtools/ransomposts/main/assets/victims.json', timeout=240))
    cut = (NOW - dt.timedelta(days=KEEP_DAYS)).strftime('%Y-%m-%d')
    return [claim(x.get('post_title'), x.get('group_name'), x.get('discovered'), x.get('country'), x.get('activity'), _pt_site(x), '', '', 'pt')
            for x in data if str(x.get('discovered', ''))[:10] >= cut]

def src_tc():   # ThreatCluster, independent first-hand collector
    data = json.loads(fetch('https://raw.githubusercontent.com/Jam0k/Ransomware-Intel/main/data/victims.json'))
    return [claim(x.get('victim'), x.get('group'), x.get('discovered'), x.get('country'), x.get('sector'), x.get('website'), '', '', 'tc')
            for x in data.get('victims', [])]

# ---------------------------------------------------------------- Cyberwatch (press-reported cyberattacks, curated)
# Valéry Rieß-Marchive (LeMagIT) curates cyberattacks reported in the world press from Google News searches in
# ~25 languages, checked manually; the same data feeds ransomware.live's "cyberattacks" and LeMagIT's Cyberhebdo.
# Served by GitHub (open CORS), so the page can also read it directly.
ISO3 = {x[:3]: x[3:] for x in "ABWAW AFGAF AGOAO AIAAI ALAAX ALBAL ANDAD AREAE ARGAR ARMAM ASMAS ATAAQ ATFTF ATGAG AUSAU AUTAT AZEAZ BDIBI BELBE BENBJ BESBQ BFABF BGDBD BGRBG BHRBH BHSBS BIHBA BLMBL BLRBY BLZBZ BMUBM BOLBO BRABR BRBBB BRNBN BTNBT BVTBV BWABW CAFCF CANCA CCKCC CHECH CHLCL CHNCN CIVCI CMRCM CODCD COGCG COKCK COLCO COMKM CPVCV CRICR CUBCU CUWCW CXRCX CYMKY CYPCY CZECZ DEUDE DJIDJ DMADM DNKDK DOMDO DZADZ ECUEC EGYEG ERIER ESHEH ESPES ESTEE ETHET FINFI FJIFJ FLKFK FRAFR FROFO FSMFM GABGA GBRGB GEOGE GGYGG GHAGH GIBGI GINGN GLPGP GMBGM GNBGW GNQGQ GRCGR GRDGD GRLGL GTMGT GUFGF GUMGU GUYGY HKGHK HMDHM HNDHN HRVHR HTIHT HUNHU IDNID IMNIM INDIN IOTIO IRLIE IRNIR IRQIQ ISLIS ISRIL ITAIT JAMJM JEYJE JORJO JPNJP KAZKZ KENKE KGZKG KHMKH KIRKI KNAKN KORKR KOSXK KWTKW LAOLA LBNLB LBRLR LBYLY LCALC LIELI LKALK LSOLS LTULT LUXLU LVALV MACMO MAFMF MARMA MCOMC MDAMD MDGMG MDVMV MEXMX MHLMH MKDMK MLIML MLTMT MMRMM MNEME MNGMN MNPMP MOZMZ MRTMR MSRMS MTQMQ MUSMU MWIMW MYSMY MYTYT NAMNA NCLNC NERNE NFKNF NGANG NICNI NIUNU NLDNL NORNO NPLNP NRUNR NZLNZ OMNOM PAKPK PANPA PCNPN PERPE PHLPH PLWPW PNGPG POLPL PRIPR PRKKP PRTPT PRYPY PSEPS PYFPF QATQA REURE ROURO RUSRU RWARW SAUSA SDNSD SENSN SGPSG SGSGS SHNSH SJMSJ SLBSB SLESL SLVSV SMRSM SOMSO SPMPM SRBRS SSDSS STPST SURSR SVKSK SVNSI SWESE SWZSZ SXMSX SYCSC SYRSY TCATC TCDTD TGOTG THATH TJKTJ TKLTK TKMTM TLSTL TONTO TTOTT TUNTN TURTR TUVTV TWNTW TZATZ UGAUG UKRUA UMIUM URYUY USAUS UZBUZ VATVA VCTVC VENVE VGBVG VIRVI VNMVN VUTVU WLFWF WSMWS XKXXK YEMYE ZAFZA ZMBZM ZWEZW".split()}
CW_URL = 'https://raw.githubusercontent.com/Casualtek/Cyberwatch/main/cyberattacks.json'
def src_cw():
    data = json.loads(fetch(CW_URL, timeout=90))
    cut = (NOW - dt.timedelta(days=KEEP_DAYS)).strftime('%Y-%m-%d')
    out = []
    for x in data:
        d = str(x.get('date') or x.get('added') or '')[:10]
        if d < cut: continue
        victim = text(x.get('victim')); url = safe_url(x.get('url'))
        if not victim and not url: continue
        out.append(rec(id='a' + hid(norm(url or victim)), type='attack', t=iso(d), title=text(x.get('title')) or victim, victim=victim,
                       domain=domain_of(x.get('domain') or ''), country=ISO3.get(str(x.get('country') or '').upper(), ''),
                       summary=text(x.get('summary') or x.get('description')), url=url, src='cw', lang='fr'))
    return out

# ---------------------------------------------------------------- SEC EDGAR 8-K
def src_sec():
    out, start = [], (NOW - dt.timedelta(days=60)).strftime('%Y-%m-%d')
    for q, want in SEC_QUERIES:
        variants = [{'q': q, 'forms': '8-K', 'dateRange': 'custom', 'startdt': start, 'enddt': NOW.strftime('%Y-%m-%d')},
                    {'q': q, 'forms': '8-K', 'startdt': start, 'enddt': NOW.strftime('%Y-%m-%d')},
                    {'q': q, 'forms': '8-K'}]
        j, last = None, None
        for v in variants:
            try:
                j = json.loads(fetch('https://efts.sec.gov/LATEST/search-index?' + urllib.parse.urlencode(v), headers={'Accept': 'application/json'}, tries=1)); break
            except Exception as e:
                last = e; time.sleep(1)
        if j is None: raise last
        for h in (j.get('hits') or {}).get('hits', []):
            s = h.get('_source') or {}
            items = set(s.get('items') or [])
            if not items & want: continue
            name = re.sub(r'\s*\(CIK[^)]*\)', '', (s.get('display_names') or [''])[0]).strip()
            name = re.sub(r'\s{2,}', ' ', name)
            adsh = s.get('adsh') or h.get('_id', '').split(':')[0]
            fn = h.get('_id', '').split(':')[1] if ':' in h.get('_id', '') else ''
            cik = str(int((s.get('ciks') or ['0'])[0]))
            url = f'https://www.sec.gov/Archives/edgar/data/{cik}/{adsh.replace("-", "")}/{fn}' if fn else \
                  f'https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}&type=8-K'
            it = 'Item 1.05 — material cybersecurity incident' if '1.05' in items else 'Item 8.01 — cybersecurity incident (other event)'
            loc = ', '.join(s.get('biz_locations') or [])
            out.append(rec(id='s' + hid(adsh), type='disclosure', t=iso(s.get('file_date')), title=f'{name} — SEC Form {s.get("form", "8-K")} {it.split(" —")[0]}',
                           victim=name, country='US', sector='SIC ' + ','.join(s.get('sics') or []), summary=f'{it}. Filed {s.get("file_date", "")}' + (f'; business location {loc}' if loc else '') + '.',
                           url=url, src='sec'))
        time.sleep(0.5)
    return out

# ---------------------------------------------------------------- RSS / Atom
NS = {'a': 'http://www.w3.org/2005/Atom', 'dc': 'http://purl.org/dc/elements/1.1/', 'c': 'http://purl.org/rss/1.0/modules/content/'}
def parse_feed(raw):
    raw = re.sub(rb'^[^<]+', b'', raw)
    root = ET.fromstring(raw)
    items = []
    for it in root.iter('item'):
        g = lambda t: (it.findtext(t) or '').strip()
        srcel = it.find('source')
        items.append({'title': g('title'), 'link': g('link') or g('guid'), 'date': g('pubDate') or it.findtext('dc:date', '', NS),
                      'desc': g('description') or it.findtext('c:encoded', '', NS), 'pub': (srcel.text or '').strip() if srcel is not None else ''})
    for e in root.iter('{http://www.w3.org/2005/Atom}entry'):
        lk = e.find("a:link[@rel='alternate']", NS)
        if lk is None: lk = e.find('a:link', NS)
        items.append({'title': e.findtext('a:title', '', NS), 'link': lk.get('href') if lk is not None else '',
                      'date': e.findtext('a:published', '', NS) or e.findtext('a:updated', '', NS),
                      'desc': e.findtext('a:summary', '', NS) or e.findtext('a:content', '', NS), 'pub': ''})
    return items

def news_items(key, name, cat, lang, url, gnews=False):
    out = []
    for x in parse_feed(fetch(url)):
        title, desc = text(x['title']), text(x['desc'])
        pub = x['pub'] or name
        if gnews:
            m = re.match(r'^(.*)\s+-\s+([^-]{2,60})$', title)
            if m: title, pub = m.group(1).strip(), x['pub'] or m.group(2).strip()
            desc = ''   # Google News descriptions only repeat the title
        if not title: continue
        if cat != 'gov' and not INCIDENT_RE.search(title + ' ' + desc[:300]): continue
        out.append(rec(id=('g' if cat == 'gov' else 'n') + hid(norm(title)[:90]), type='advisory' if cat == 'gov' else 'news',
                       t=iso(x['date']) or NOW.strftime('%Y-%m-%dT%H:%M:%SZ'), title=title, summary=desc[:500],
                       url=safe_url(x['link']), src=key, lang=lang, pub=pub))
    return out

def gnews_url(q, lang, gl):
    return 'https://news.google.com/rss/search?' + urllib.parse.urlencode({'q': q + ' when:3d', 'hl': lang if lang != 'en' else f'en-{gl}', 'gl': gl, 'ceid': f'{gl}:{lang}'})

# ---------------------------------------------------------------- run
def main():
    os.makedirs(OUT, exist_ok=True)
    prev = []
    for p in (PREV, os.path.join(OUT, 'incidents.json')):
        try:
            prev = json.load(open(p)); log(f'previous data: {p} ({len(prev)} records)'); break
        except Exception:
            pass
    jobs = {'rl': ('ransomware.live — leak-site claims', 'claims', src_rl_victims),
            'rl_att': ('ransomware.live — press-reported cyberattacks', 'attacks', src_rl_attacks),
            'cw': ('Cyberwatch — press-reported cyberattacks, curated (LeMagIT)', 'attacks', src_cw),
            'pt': ('ransomware.live mirror (privtools, GitHub)', 'claims', src_pt),
            'tc': ('ThreatCluster Ransomware-Intel (GitHub)', 'claims', src_tc),
            'sec': ('SEC EDGAR — Form 8-K cyber disclosures', 'regulatory', src_sec)}
    oldest = min((x.get('t') or '9') for x in prev if x.get('type') == 'claim') if prev else ''
    need_history = not prev or oldest[:10] > (NOW - dt.timedelta(days=KEEP_DAYS - 45)).strftime('%Y-%m-%d')
    if need_history: jobs['pt_full'] = (f'ransomware.live history bootstrap, {KEEP_DAYS} days (privtools)', 'claims', src_pt_full)
    for key, name, cat, lang, url in RSS:
        jobs[key] = (name, cat, (lambda k=key, n=name, c=cat, l=lang, u=url: news_items(k, n, c, l, u)))
    for key, lang, gl, q in GNEWS:
        label = {'gn_indcyber': 'Industrial Cyber (via Google News)', 'gn_cybernews': 'Cybernews (via Google News)', 'gn_rhc': 'Red Hot Cyber (via Google News)',
                 'gn_trade_en': 'Food & dairy trade press, EN (via Google News)', 'gn_trade_fr': 'Presse agroalimentaire, FR (via Google News)'}.get(key, f'Google News — {lang.upper()}/{gl}')
        jobs[key] = (label, 'trade' if key.startswith('gn_trade') else 'press' if key in ('gn_indcyber', 'gn_cybernews', 'gn_rhc') else 'aggregator', (lambda k=key, l=lang, g=gl, q=q: news_items(k, 'Google News', 'aggregator', l, gnews_url(q, l, g), True)))
    status = {'sources': {}, 'built_utc': ''}
    def run(item):
        key, (name, cat, fn) = item
        if key in OFFLINE: return key, name, cat, None, 'skipped', 0
        t0 = time.time()
        try:
            r = [x for x in fn() if x]
            return key, name, cat, r, '', time.time() - t0
        except Exception as e:
            return key, name, cat, None, f'{type(e).__name__}: {str(e)[:160]}', time.time() - t0
    fresh = []
    with ThreadPoolExecutor(12) as ex:
        for key, name, cat, r, err, sec in ex.map(run, jobs.items()):
            st = {'name': name, 'cat': cat, 'ok': r is not None, 'rows': len(r or []), 'seconds': round(sec, 1)}
            if err == 'skipped': st['skipped'] = True
            elif err: st['error'] = err
            if r:
                ts = [x['t'] for x in r if x['t']]
                if ts: st['latest'] = max(ts)
                for x in r: x['src'] = 'pt' if key == 'pt_full' else key
                fresh += r
            status['sources'][key] = st
            log(f"{key:10s} {'ok ' if r is not None else 'ERR'} {len(r or []):5d}  {err}")
    if 'pt_full' in status['sources']:          # history bootstrap is the same source as the mirror: report it there
        h = status['sources'].pop('pt_full')
        if 'pt' in status['sources']: status['sources']['pt']['history_rows'] = h.get('rows', 0)
    # merge: earliest detection ("seen") is kept; sources are accumulated
    now_s = NOW.strftime('%Y-%m-%dT%H:%M:%SZ')
    byid = {x['id']: x for x in prev if x.get('id')}
    for x in fresh:
        s = {'k': x.pop('src'), 't': x.get('t', '')}
        if x.get('url') and x['type'] != 'claim': s['url'] = x['url']
        if x.get('pub'): s['pub'] = x.pop('pub')
        o = byid.get(x['id'])
        if o is None:
            x['seen'] = now_s if prev else (x['t'] or now_s)   # first build: no detection history, use the event time
            x['srcs'] = [s]; x['src'] = s['k']; byid[x['id']] = o = x
        else:
            for f in ('country', 'sector', 'domain', 'summary', 'victim'):
                if not o.get(f) and x.get(f): o[f] = x[f]
            if x.get('t') and (not o.get('t') or x['t'] < o['t']): o['t'] = x['t']
            if not any(y['k'] == s['k'] for y in o.get('srcs', [])): o.setdefault('srcs', []).append(s)
        if not o.get('url') and s.get('url'): o['url'] = s['url']
    cut = (NOW - dt.timedelta(days=KEEP_DAYS)).strftime('%Y-%m-%d')
    allr = [x for x in byid.values() if (x.get('t') or x.get('seen', '')) >= cut]
    for x in allr:
        if x.get('victim') == x.get('title'): x.pop('victim')
        for f in [f for f, v in x.items() if v in ('', [], None)]: x.pop(f)
        if not x.get('t'): x['t'] = x.get('seen', now_s)
    allr.sort(key=lambda x: (x.get('seen', ''), x.get('t', '')), reverse=True)
    status['built_utc'] = now_s
    status['count'] = len(allr)
    status['new'] = sum(1 for x in allr if x.get('seen') == now_s)
    with open(os.path.join(OUT, 'incidents.json'), 'w') as f:
        f.write('[\n' + ',\n'.join(json.dumps(x, ensure_ascii=False, separators=(',', ':')) for x in allr) + '\n]\n')
    with open(os.path.join(OUT, 'status.json'), 'w') as f:
        json.dump(status, f, indent=1)
    if os.path.dirname(PREV):
        os.makedirs(os.path.dirname(PREV), exist_ok=True)
        with open(PREV, 'w') as f: json.dump(allr, f, ensure_ascii=False, separators=(',', ':'))
    ok = sum(1 for s in status['sources'].values() if s['ok'])
    log(f'{len(allr)} records ({status["new"]} new), {ok}/{len(status["sources"])} sources ok')

if __name__ == '__main__':
    main()
