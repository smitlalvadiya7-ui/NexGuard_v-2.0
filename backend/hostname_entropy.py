"""
Hostname randomness (DGA) detection — Phase 1a of ROAD_TO_90.md.

Legitimate hostnames are pronounceable and dictionary-ish (hdfcbank, flipkart,
my-portfolio). Machine-generated ones are not:

    sp3ct-meslor-biz8-varnex-pisol.pages.dev
    77v-bqgb7-8074z-cy9gp-q6su.pages.dev
    qtwiz553bf-vlypxskru-1d8c3f-fyn9t.pages.dev

Those three are real: 47 of the 93 misses in post-fix benchmark run 4 were one
Cloudflare Pages campaign of exactly that shape, every URL scored at 34 — six
points under SUSPICIOUS. On that corpus, separating this cluster alone moves
recall 38.4% -> 69.5% (ROAD_TO_90.md §1b).

WHAT THIS SIGNAL IS FOR
-----------------------
CORROBORATION, never conviction. Some legitimate hosts have random-looking
labels — CI preview deploys and CDN nodes (ci-7f3a9b.vercel.app,
d1a2b3c4e5f6g7.cloudfront.net). So a random label does not add risk on its own;
in aggregator.full_scan it satisfies the corroboration gate, which lets the
lexical ML back into the blend on a shared-hosting tenant. If nothing else
votes, the score does not move.

DESIGN NOTES
------------
* Thresholds, not a model. The plan says to calibrate simple features against
  Tranco negatives first and only train if that proves insufficient.
  tests/test_hostname_entropy.py scores 5000 real Tranco labels through
  label_randomness_score() with the established-domain exemption bypassed and
  fails if more than 1% look random — that test IS the calibration.
* Evidence has to ACCUMULATE (RANDOM_SCORE_MIN). No single feature convicts,
  because every one of them has legitimate counter-examples: build hashes are
  digit-heavy, transliterated labels have long consonant runs (vseinstrumenti),
  and non-English labels are not in any word list.
* A single random-looking token is never enough — that is precisely the CI
  preview / CDN node shape. Only the multi-token DGA shape accumulates.
* Established registrables (Tranco top-100k) are exempt: they ARE the real
  site, and their transliterated labels would be the first false positives.

Leaf-ish module: imports tldextract, top_domains and shared_hosting only, so it
can be used from aggregator and from the eval scripts without an import cycle.

Public surface
--------------
  analysed_label(host)            -> the label the attacker chose, or ""
  label_features(label)           -> the seven measurements
  label_randomness_score(label)   -> accumulated evidence points
  hostname_randomness(host)       -> {"label", "score", "random", "reason", "features"}
  is_random_hostname(host)        -> bool
  RANDOM_SCORE_MIN
"""

from __future__ import annotations

import math
import re
from functools import lru_cache

import tldextract

from shared_hosting import SHARED_HOSTING_SUFFIXES
from top_domains import is_established_registrable_host

# Offline bundled PSL snapshot, private section included — same configuration as
# shared_hosting and top_domains, so a tenant page keeps its own label instead
# of collapsing into the platform's registrable.
_PSL = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

_IPV4 = re.compile(r"\A\d{1,3}(\.\d{1,3}){3}\Z")
_TOKEN_SPLIT = re.compile(r"[-_]+")
_VOWELS = frozenset("aeiouy")   # 'y' counts as a vowel: it breaks consonant runs
                                # in real labels (vlypxskru, myportfolio)

# --- thresholds (calibrated in tests/test_hostname_entropy.py) --------------

RANDOM_SCORE_MIN = 4        # evidence points needed before a label is "random"
_MIN_TOKEN_LEN = 4          # shorter tokens are too small to judge (ci, pr, 42)
_MIN_DICT_WORD_LEN = 4      # below this a token carries no dictionary opinion
_MIN_WORD_PART_LEN = 3      # smallest piece a compound may decompose into
_GIBBERISH_CONSONANT_RUN = 4
_GIBBERISH_VOWEL_RATIO = 0.25
_STRONG_CONSONANT_RUN = 5
_DIGIT_RATIO_HIGH = 0.15
_ENTROPY_HIGH = 3.6
_MULTI_TOKEN_MIN = 3        # "many tokens, none of them words" needs 3+
_MANY_TOKEN_MIN = 4         # ...and a fourth such token is further evidence

# Common English / web / product vocabulary. Deliberately small and hand-kept:
# its only job is to recognise a HUMAN-CHOSEN label, and every entry can only
# make the detector more conservative (a recognised word never adds evidence).
# A token counts as human-made when it decomposes ENTIRELY into entries of
# >= _MIN_WORD_PART_LEN, so "cloudbank" and "handbook" are covered without
# "warnor" passing on the strength of "warn".
#
# English-only, and that is a known limit: German compounds in the Tranco list
# (deutsche-wirtschafts-nachrichten) look wordless to it. They are established
# registrables, so the exemption in hostname_randomness covers them.
_WORDS = frozenset("""
preview staging sandbox landing starter template portal gateway wallet
dashboard checkout onboarding signin signup logout profile settings billing
invoice receipt refund payout payroll vendor supplier customer tenant
namespace endpoint webhook runtime pipeline release rollout revision snapshot
cluster container registry package bundle asset static media upload download

about access account admin adobe agency alert alpha analytics android animal answer
api app apple apply archive area article asset audio auth author auto award back
backup badge balance bank base basket batch beauty best beta bike bill billing bird
blog board board body book booking boost bottom brand bread break bridge broker
browse budget build builder bulk business button buy cache cake calc calendar call
camera camp campus car card care career cart case cash cast catalog cause center
central chain chair chance change channel chapter charge charity chart chat cheap
check chef child china choice church cinema circle city civil claim class classic
clean clear click client climate clinic clock close cloud club coach coast code
coffee coin cold collect college color comic common community company compare
compute concept concert config connect console consult contact content contest
context control cook cool copy core corner corp cost count country couple coupon
course court cover craft create credit crew cricket crypto culture cup currency
custom cycle daily dance dark data date deal dealer debt decor deep default defense
degree deliver demo dental deploy depot design desk detail dev develop device
diamond diary diet digital direct discount discover disk display doc docs doctor
dog domain donate door double download draft drama draw dream dress drink drive
driver drop drug dubai each early earn earth east easy eat eco edge edit editor
education effect egg elite email empire employ empty end energy engine english
enter entry equal equip error escape essay estate euro event exam example exchange
exclusive expert explore export express extra eye fabric face fact factory fair
faith family famous fan fantasy farm fashion fast father favorite feature feed
feedback festival field file fill film filter final finance find fine finish fire
first fish fit fitness five fix flag flash flat fleet flight floor flow flower
focus folder follow font food foot football force forecast forest forever forge
fork form format forum forward found four frame free freedom fresh friend front
fruit full fund funny furniture future gadget gain gallery game gaming garage
garden gate gear general generator gift girl give glass global glow goal gold golf
good google gospel grace grade grand graph graphic great green grid grocery group
grow guard guide guitar gulf guru hack hair half hand handbook happy hard hardware
harvest hash hat head health heart heat heaven heavy hello help hero hidden high
hill hint hire history hobby hold holiday home honey hook hope horse hospital host
hosting hotel hour house human hunt hydro icon idea image impact import income
index india industry info inn innovation insight inspect install instant institute
insurance intel inter invest invoice iron island issue item jack japan jazz jewel
job join joint journal journey joy judge juice jump junior just keep key keyboard
kick kid kind king kitchen knight know lab label labor lady lake lamp land landing
lane language laptop large laser last late latest laugh launch law layer lead
leader leaf league learn lease leather lecture left legal legend lemon lend length
lens less lesson letter level library life light like limit line link lion liquid
list listen little live living load loan lobby local locate lock lodge log logic
login logo long look loop lord lost lot lotus love lower loyal luck lucky lunch
luxury machine made magazine magic mail main maintain major make maker mall manage
manager manual manufacture many map marine mark market marriage mars mask master
match material math matrix matter max mayor meal mean measure meat media medical
medicine meet mega member memory menu merchant merge message metal meter method
metro micro mid middle might mile military milk mill mind mine mini minister minute
mirror miss mission mobile mode model modern module moment money monitor monkey
month moon more morning mortgage most mother motion motor mount mountain mouse
mouth move movie much multi music must mutual myself name nation native natural
nature navi navy near neat need neighbor nerve nest net network never news next
nice night nine node noise none noodle north note notice novel now number nurse
nutrition object observe ocean offer office official offline often oil okay old
olive online only open opera operate opinion option orange orbit order organic
organize origin other outdoor outlet output outside over owner pack package page
paint pair palace panel paper parent park parking part partner party pass passion
password past patch path patient pattern pay payment peace peak pearl pen pencil
people pepper perfect perform period person pet phone photo phrase physical piano
pick picture piece pilot pin pink pipe pitch pixel pizza place plan planet plant
plastic plate platform play player plaza plug plus pocket podcast point poker
police policy politics pool poor pop popular port portal portfolio position
positive post potato power practice pray precise premier premium prepare present
press pretty prevent price pride primary prime prince principal print prior private
prize problem process produce product profile profit program project promo promote
proof proper property protect proud provide public publish pulse pump pure purple
purpose push quality quantity quarter queen query question quick quiet quiz quote
race radio rail rain raise rally random range rank rapid rare rate rating reach
react read reader ready real reality realty reason rebel receipt receive recipe
record recover recruit red reduce refer reform refresh refund region register
regular relax release relief remote remove render rent repair repeat replace report
request require rescue research reserve reset resident resource respect response
rest restaurant result resume retail retire return reveal reverse review reward
rich ride right ring rise risk river road robot rock rocket role roll roof room
root rose round route royal rubber rugby rule run runner rural rush safe safety
sail salad salary sale salon salt sample sand save saving scale scan scene schedule
scheme school science scope score screen script sea search season seat second
secret section secure security seed seek select self sell semi send senior sense
serial series serious serve server service session set setting seven shade shadow
shake shape share sharp shed sheet shelf shell shield shift shine ship shirt shock
shoe shoot shop shopping shore short shot show shower side sign signal silk silver
simple single sister site size sketch ski skill skin sky sleep slide slim slot slow
small smart smile smoke snack snap snow soap social society sock soft software soil
solar sold soldier sole solid solution solve some song sonic soon sort soul sound
soup source south space spain spam span spare spark speak special speed spell spend
sphere spice spider spin spirit split sport spot spray spread spring square stable
stack staff stage stair stake stand star start state station status stay steam
steel step stick still stock stone stop storage store storm story straight strategy
stream street strength stress strike string strong struct student studio study
stuff style subject submit subscribe success such sudden sugar suit summer summit
sun super supply support sure surface surf surprise survey survive sweet swift
swim switch symbol system table tablet tackle tactic tag tail take tale talent talk
tank tape target task taste tax taxi tea teach team tech technical technology teen
tele tell temple ten tenant tennis term terminal test text thank theater theme
therapy thing think third thought thread three thrive throw thumb ticket tide tie
tiger tile time tiny tip tire title today todo together token tomato tomorrow tone
tool tooth top topic torch total touch tour tourism toward tower town toy trace
track trade tradition traffic trail train trainer transfer transit translate
transport trash travel treat tree trend trial tribe trick trip triple trophy
trouble truck true trust truth try tube tune tunnel turbo turn tutor tweet twin
twist type ultra umbrella uncle under union unique unit unite universal university
unlock until upgrade upload upper urban urgent usage user usual utility vacation
valid valley value van vault vector vehicle vendor venture venue verify version
very vessel veteran video view village vintage viral virtual virus vision visit
visual vital vitamin voice volume vote voucher voyage wage wait wake walk wall
wallet want war ward ware warm warn warranty wash waste watch water wave way wealth
weapon wear weather web wedding week weight welcome welfare well west wheel where
which while white whole wide widget wife wifi wiki wild will win wind window wine
wing winner winter wire wise wish witness wizard woman wonder wood wool word work
worker workshop world worth wrap write writer yacht yard year yellow yes yoga young
your youth zebra zero zone zoom
""".split())


# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    """Shannon entropy, bits per symbol, over the characters of s."""
    if not s:
        return 0.0
    return -sum(
        (n / len(s)) * math.log2(n / len(s))
        for n in (s.count(c) for c in set(s))
    )


def _max_consonant_run(s: str) -> int:
    """Longest run of consecutive consonants. Digits and separators break a
    run: 'a1bcd' is not a 4-consonant word shape."""
    best = run = 0
    for ch in s:
        if ch.isalpha() and ch not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


@lru_cache(maxsize=4096)
def _decomposes_into_words(letters: str) -> bool:
    """True when letters split ENTIRELY into dictionary words of >= 3 chars."""
    if not letters:
        return True
    return any(
        letters[:n] in _WORDS and _decomposes_into_words(letters[n:])
        for n in range(_MIN_WORD_PART_LEN, len(letters) + 1)
    )


def _has_dict_word(token: str) -> bool:
    """
    True when the token is a word, or a compound of words — 'cloudbank',
    'team-handbook'. That is how humans name things.

    Whole-token decomposition, NOT substring matching. Substring matching read
    'warnor' as a word because it opens with 'warn', and 'mostik' because of
    'most' — which let two hosts of the pronounceable-nonsense campaign through.
    A chance prefix is not evidence that a human chose the token.
    """
    letters = "".join(c for c in token if c.isalpha())
    if len(letters) < _MIN_DICT_WORD_LEN:
        return False
    return letters in _WORDS or _decomposes_into_words(letters)


def _is_gibberish_token(token: str) -> bool:
    """
    A token that no human would choose: long enough to judge, not a word, and
    showing at least one machine tell — letters spliced with digits, an
    unpronounceable consonant run, or almost no vowels.
    """
    if len(token) < _MIN_TOKEN_LEN:
        return False
    letters = [c for c in token if c.isalpha()]
    if not letters:
        return False                      # pure digits: a version / PR number
    if _has_dict_word(token):
        return False
    mixed_digits = any(c.isdigit() for c in token)
    vowel_ratio = sum(c in _VOWELS for c in letters) / len(letters)
    return (
        mixed_digits
        or _max_consonant_run(token) >= _GIBBERISH_CONSONANT_RUN
        or vowel_ratio < _GIBBERISH_VOWEL_RATIO
    )


def label_features(label: str) -> dict:
    """
    The seven measurements ROAD_TO_90.md Phase 1a names, plus the two derived
    token counts the scorer uses.

    'word tokens' are the tokens big enough and alphabetic enough to judge —
    'pr' and '1234' in 'pr-1234-abc123' are not opinions about randomness, and
    counting them would have made that legitimate preview host look like a
    multi-token DGA label.
    """
    lab = (label or "").lower().strip()
    tokens = [t for t in _TOKEN_SPLIT.split(lab) if t]
    word_tokens = [t for t in tokens
                   if len(t) >= 3 and any(c.isalpha() for c in t)]
    alnum = "".join(c for c in lab if c.isalnum())
    n_dict = sum(1 for t in word_tokens if _has_dict_word(t))
    return {
        "label": lab,
        "entropy": round(_entropy(alnum), 4),
        "digit_ratio": round(sum(c.isdigit() for c in lab) / len(lab), 4) if lab else 0.0,
        "hyphen_count": lab.count("-"),
        "token_count": len(tokens),
        "mean_token_length": (round(sum(len(t) for t in tokens) / len(tokens), 4)
                              if tokens else 0.0),
        "dict_word_ratio": (round(n_dict / len(word_tokens), 4) if word_tokens else 0.0),
        "max_consonant_run": _max_consonant_run(lab),
        "word_token_count": len(word_tokens),
        "gibberish_token_count": sum(1 for t in word_tokens if _is_gibberish_token(t)),
    }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def label_randomness_score(label: str, *, features: dict | None = None) -> int:
    """
    Accumulated evidence that a human did not choose this label.

    No single feature convicts, because each one has legitimate
    counter-examples: build hashes are digit-heavy, transliterated labels have
    long consonant runs, and non-English labels are in no word list. Only the
    combination — several unpronounceable tokens, none of them words — reaches
    RANDOM_SCORE_MIN.

    Deliberately NOT scored: a single long random token. That is the CI-preview
    and CDN-node shape (d1a2b3c4e5f6g7.cloudfront.net), and the measured miss
    cluster is entirely multi-token, so there is nothing to gain and a real
    false-positive risk in reaching for it.
    """
    f = features if features is not None else label_features(label)
    if not f["label"]:
        return 0
    score = 0
    if f["word_token_count"] >= _MULTI_TOKEN_MIN and f["dict_word_ratio"] == 0.0:
        score += 2                        # many tokens, not one of them a word
    if f["word_token_count"] >= _MANY_TOKEN_MIN and f["dict_word_ratio"] == 0.0:
        # The pronounceable-nonsense shape (sp29ct-qarnel-biz-mostik-havqen):
        # every token obeys consonant-vowel rules, so none looks generated on
        # its own. Four-plus of them with no real word among them is the tell.
        # Measured: takes the caught share of run 4's misses from 38 to 50 and
        # the pages.dev cluster from 38/52 to 50/52, while the flag rate over
        # 99,599 Tranco labels moves only 0.005% -> 0.012%.
        score += 1
    if f["gibberish_token_count"] >= 2:
        score += 2                        # never on one token alone
    if f["gibberish_token_count"] >= 3:
        score += 1
    if f["digit_ratio"] >= _DIGIT_RATIO_HIGH:
        score += 1
    if f["max_consonant_run"] >= _STRONG_CONSONANT_RUN:
        score += 1
    if f["entropy"] >= _ENTROPY_HIGH:
        score += 1
    return score


def _reason(f: dict, score: int) -> str:
    return (
        f"machine-generated hostname label '{f['label']}' "
        f"({f['gibberish_token_count']}/{f['word_token_count']} unpronounceable "
        f"tokens, entropy {f['entropy']:.2f}, digits {f['digit_ratio']:.0%}, "
        f"longest consonant run {f['max_consonant_run']}, evidence {score})"
    )


# ---------------------------------------------------------------------------
# Host-level entry points
# ---------------------------------------------------------------------------

def analysed_label(host: str) -> str:
    """
    The part of the hostname whoever published the page actually chose.

    On shared hosting that is the TENANT label, not the platform suffix:
    'pages.dev' is Cloudflare's, and folding it into every tenant's
    measurements would add the same constant to all of them and wash the
    signal out. Off shared hosting it is the registrable label.

    Returns "" for anything unparseable — an IP literal, a bare 'localhost', a
    host with no public suffix — so a degenerate input can never manufacture a
    signal.
    """
    d = (host or "").lower().strip().rstrip(".")
    if not d or _IPV4.match(d):
        return ""
    if d.startswith("www."):
        d = d[4:]
    # Manual shared-hosting suffixes first: some (gitbook.io) are deliberately
    # absent from the PSL private section, so tldextract alone would return the
    # platform's own label instead of the tenant's.
    for suf in SHARED_HOSTING_SUFFIXES:
        if d.endswith("." + suf):
            return d[: -(len(suf) + 1)].rsplit(".", 1)[-1]
    try:
        ext = _PSL(d)
    except Exception:
        return ""
    if not ext.suffix or not ext.domain:
        return ""
    return ext.domain


def hostname_randomness(host: str) -> dict:
    """
    {"label", "score", "random", "reason", "features"} for a hostname.

    Established registrables (Tranco top-100k) are exempt outright: they ARE
    the real site, and consonant-heavy transliterations like vseinstrumenti.ru
    would otherwise be the first false positives this feature produced.
    """
    label = analysed_label(host)
    quiet = {"label": label, "score": 0, "random": False, "reason": None,
             "features": {}}
    if not label:
        return quiet
    try:
        if is_established_registrable_host(host):
            return quiet
    except Exception:
        pass                              # fail neutral, never fail loud
    f = label_features(label)
    score = label_randomness_score(label, features=f)
    is_random = score >= RANDOM_SCORE_MIN
    return {
        "label": label,
        "score": score,
        "random": is_random,
        "reason": _reason(f, score) if is_random else None,
        "features": f,
    }


def is_random_hostname(host: str) -> bool:
    """True when the hostname label looks machine-generated. Corroborating
    signal only — see the module docstring."""
    return hostname_randomness(host)["random"]
