# YARA-subset rule matching

`codevanta.analysis.yara_subset` evaluates a bounded subset of real YARA
rule syntax over the raw bytes of any file — read-only, offline, pure
standard library, and with an evidence record behind every claim. It exists
so analysts can reuse the YARA rule corpus that already circulates inside
CODEVANTA's evidence model, without importing the YARA engine itself.
Reference grammar and semantics: [VirusTotal/yara](https://github.com/VirusTotal/yara).

The target file is scanned as raw bytes, so any file matches — not only
binaries the loader understands. Python surface:

```python
from pathlib import Path

from codevanta.analysis.yara_subset import load_rules_file, match_rules, parse_rules

rules = parse_rules('rule hello { strings: $a = "hello" condition: $a }')
rules = load_rules_file(Path("corpus.yar"))          # same, from disk

report = match_rules(
    Path("sample.bin"),
    rules_text='rule marker { strings: $m = "codevanta" condition: #m >= 1 }',
    # rules_path=Path("corpus.yar"),                  # mutually exclusive
    # max_strings=200_000, max_matches_per_string=64, # recorded-offset caps
)
report.matches        # rules whose condition held, sorted by rule name
report.evaluations    # every rule, each with its condition_satisfied verdict
report.to_dict()      # JSON-safe payload (offsets as hex strings)
```

Anything outside the subset raises the typed `AnalysisError` naming the
rule and the offending token — nothing is silently ignored, so a corpus
rule that looks supported but is not fails loudly instead of matching
less than it would in real YARA.

## Supported grammar

```ebnf
rules       = { comment } , rule , { comment , rule } ;
rule        = "rule" , IDENT , "{" , [ meta ] , [ strings ] , condition , "}" ;
meta        = "meta:" , { IDENT , "=" , ( STRING | INT | "true" | "false" ) } ;
strings     = "strings:" , { string_entry } ;
string_entry= "$" , IDENT , "=" , ( STRING , { modifier } | hex_string ) ;
modifier    = "nocase" | "wide" ;
hex_string  = "{" , { HEXPAIR | jump } , "}" ;
HEXPAIR     = two of [0-9A-Fa-f?] , e.g. "AA" | "??" | "A?" | "?5" ;
jump        = "[" , INT , "]" | "[" , INT , "-" , INT , "]" ;   (* both <= 64 *)
condition   = or_expr ;
or_expr     = and_expr , { "or" , and_expr } ;
and_expr    = not_expr , { "and" , not_expr } ;
not_expr    = "not" , not_expr | primary ;
primary     = "(" , or_expr , ")"
            | "all" , "of" , string_set | "any" , "of" , string_set
            | INT , "of" , string_set
            | "$" , IDENT                                  (* matched? *)
            | "#" , IDENT , cmp , INT                      (* match count *)
            | "filesize" , cmp , INT ;
string_set  = "them" | "(" , id_spec , { "," , id_spec } , ")" ;
id_spec     = "$" , IDENT , [ "*" ] ;                      (* wildcard prefix *)
cmp         = ">" | ">=" | "<" | "<=" | "==" | "!=" ;
INT         = decimal or 0x-hex literal ;
comment     = "//" … end-of-line | "/*" … "*/" ;
```

Meta blocks are preserved verbatim on the rule and echoed in the report;
they never influence matching.

## Matching semantics

* Text strings are searched over the raw file bytes (pattern encoded as
  UTF-8). **Deviation from stock YARA:** `wide` *adds* a UTF-16LE
  interleaved scan while the ASCII scan stays on — YARA's bare `wide`
  searches UTF-16LE only (there it takes `wide ascii` to get both).
* `nocase` folds ASCII `A-Z` only, on both encodings.
* Every occurrence is reported, including overlapping ones (`"aa"` matches
  `"aaaa"` at 0, 1 and 2), each with its raw file offset.
* Hex strings match over raw bytes: `??` matches any byte, `A?` / `?5`
  match a nibble, `[n-m]` skips n..m bytes (backtracking-safe sweep), and
  a pattern may end exactly at end-of-file.
* `filesize` is the byte length of the file.
* Results are deterministic: report rows are sorted by rule name, string
  rows within a rule by string id.

## Confidence semantics

| Finding | Confidence | Why |
|---------|------------|-----|
| A string match at an offset | `certain` | the bytes are provably in the file at that offset |
| The rule conclusion (condition verdict) | `medium` | an inference from the matched bytes, not a direct fact |
| Report-level summary | `medium` | aggregates rule conclusions |

## Bounds

Every bound that fires is reported through `truncated` flags or warnings —
never silently. Counting never stops, so `#a` conditions stay truthful
even when recorded offsets are cut.

| Bound | Default | Effect |
|-------|---------|--------|
| Total match offsets recorded (`max_strings`) | 200 000 | further offsets counted, not recorded; `truncated: true` + warning |
| Offsets kept per string id (`max_matches_per_string`) | 64 | kept row is short, `count` holds the true total, `truncated: true` |
| Hex jump upper bound `[n-m]` | 64 | larger or unbounded (`[*]`, `[n-]`) rejected at parse time |
| Condition nesting depth | 16 | deeper rules rejected at parse time |
| Strings per rule | 256 | larger rules rejected at parse time |
| Warnings kept | 32 | dropped warnings are counted in a final summary line |

## Not supported (rejected with a typed error)

The subset refuses rather than approximates, because a silently weakened
rule would report *fewer* matches than the same rule in real YARA:

* regex strings (`/re/`), and every string modifier except `nocase` and
  `wide` (`ascii`, `fullword`, `private`, `xor`, `base64`, ...);
* hex alternation `( AA | BB )`, unbounded jumps `[*]` / `[n-]`, jump
  bounds above 64, odd hex digit counts;
* `import "pe"` and all module conditions (`pe.*`, `math.*`, `hash.*`,
  ...), `for .. of` / `for .. in` loops, `at` / `in` position operators,
  `@a` / `!a` occurrence syntax, integer arithmetic, boolean literals;
* rule tags (`rule x : tag`), `global` / `private` rules, namespaces,
  `include` files, `KB`/`MB` size suffixes;
* duplicate rule names, duplicate string ids, empty rules files,
  references to strings a rule never declared.

## Why a subset

The goal is interop with the byte-level core of circulating YARA rules —
text and hex patterns with plain boolean conditions — inside CODEVANTA's
evidence model: every match carries a provable offset (`certain`), every
rule verdict carries its fired strings and counts (`medium`), and every
bound is reported rather than truncating silently. Full YARA semantics
(dictionaries, loops, modules, regex) would pull in an engine dependency
and a much larger trust surface; the stdlib-only subset keeps the lane
auditable and deterministic. Rules outside the subset fail loudly with the
rule and token named, so they can be ported by hand instead of quietly
matching less.
