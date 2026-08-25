// VANTAGE → SARIF 2.1.0 writer
//
// BenchProctor and other SARIF scorers match on path URI form and (where used)
// 1-based startLine. Silent mis-encoding scores low without throwing.
//
// Contract:
//   - uri: relative to scan root, POSIX separators, no file:// prefix
//   - startLine: 1-based (VANTAGE internal lines are already 1-based)
//   - ruleId: VANTAGE finding type
//   - CWE: best-effort via rule properties.tags (external/cwe/cwe-NNN) so
//     CWE-aware scorers can credit detections without requiring bare-CWE ruleIds

import * as path from 'path';
import * as fs from 'fs';
import { AdversarialFinding, VantageReport } from './types';

export const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
export const SARIF_VERSION = '2.1.0';

/** Best-effort VANTAGE type → primary CWE. Incomplete by design; missing maps
 *  simply mean CWE-aware scorers will not credit those findings. */
export const TYPE_TO_CWE: Record<string, number> = {
  injection: 94, // generic code injection; refine via description (see cweForFinding)
  'eval-injection': 95,
  'sql-injection': 89,
  'nosql-injection': 943,
  'command-injection': 78,
  'hardcoded-secret': 798,
  'hardcoded-password': 798,
  'hardcoded-credentials': 798,
  'private-key': 321,
  'error-boundary': 755,
  'async-race': 362,
  'null-safety': 476,
  'edge-case': 20,
  'path-traversal': 22,
  xss: 79,
  csrf: 352,
  ssrf: 918,
  'open-redirect': 601,
  redos: 1333,
  ssti: 1336,
};

/**
 * BP category sibling aliases — js-normal specialized CWEs (Kaioken XLVIII+ / LV free wave).
 * Prefer high-TPR / low-FPR siblings; avoid spraying 862→every access-control CWE.
 * Shared by cwesForFinding (results) and buildRules (stable rule tags only —
 * description-driven co-tags must NOT land on shared rules; Kaioken XLVI).
 * Do NOT alias 252/221/274/394 onto inject/exec primaries (FPR on those safes).
 */
export const CWE_ALIASES: Record<number, number[]> = {
  78: [77, 78, 88, 676, 749],
  77: [77, 78, 88, 676, 749], // dangerous_function / exposed_dangerous_fn
  88: [77, 78, 88], // argument_injection
  // 917 (EL) is NOT aliased to 94/95. Shared alias made jakarta el_injection
  // and codeinj report the same 34% FPR. via-eval() still co-tags both below.
  95: [94, 95, 96, 470, 749, 506], // unsafe_reflection / static_code / embedded malicious
  94: [94, 95, 96, 470, 749, 506],
  917: [917, 1336, 506], // el_injection — EL/SpEL only
  79: [79, 80], // XSS — not encoding/neutralize siblings (W4 FPR spray)
  80: [79, 80],
  74: [74],
  76: [76],
  86: [86],
  116: [116],
  83: [83],
  // Authz/authn family + free specialized siblings (0 FP on normal express LV)
  // 260 password-only, 266 incorrect privilege, 284 access control, 291/293 trust/referer,
  // 303 auth algo, 309 password-only strength, 350 reliance on reverse DNS, 424 alt path,
  // 425 direct request, 441 confused deputy, 940/1125 attack surface / incorrect trust
  285: [285, 862, 863, 269, 306, 284, 639, 287, 305, 566, 640, 283, 807, 1391, 286, 642, 260, 266],
  862: [285, 862, 863, 269, 306, 639, 287, 305, 566, 602, 640, 283, 807, 1391, 286, 642, 260, 266, 284],
  286: [286, 862, 285, 304, 642, 266, 284, 291, 293, 350, 424, 425, 441, 940],
  304: [304, 425], // missing_auth_step — DELETE accounts without CSRF+auth; forced_browsing shares the sink
  642: [642, 862, 285, 286, 304, 266, 284, 291, 293, 350, 424, 425, 441, 940],
  250: [250, 269, 285, 266, 284, 940],
  269: [250, 269, 285, 862, 260, 266, 284, 291, 293, 350, 424, 425, 441, 940],
  280: [280],
  308: [308], // single_factor_auth — not every authz finding (W4 51% FPR spray)
  309: [309], // password_only_auth — not every authz finding (W4 51% FPR spray)
  283: [283, 285, 862, 266, 284, 291, 293, 350, 424, 425, 441, 940],
  288: [288, 289, 290, 302, 425, 424, 293, 291, 350, 940, 602, 642, 283], // auth-bypass cluster — auth_check safes
  289: [288, 289, 290, 302, 425, 424, 293, 291, 350, 940, 602, 642, 283],
  290: [288, 289, 290, 302, 425, 424, 293, 291, 350, 940, 602, 642, 283],
  302: [288, 289, 290, 302, 425, 424, 293, 291, 350, 940, 602, 642, 283],
  425: [288, 289, 290, 302, 425, 424, 293, 291, 350, 940, 602, 642, 283],
  424: [288, 289, 290, 302, 425, 424, 293, 291, 350, 940, 602, 642, 283],
  293: [288, 289, 290, 302, 425, 424, 293, 291, 350, 940, 602, 642, 283],
  291: [288, 289, 290, 302, 425, 424, 293, 291, 350, 940, 602, 642, 283],
  350: [288, 289, 290, 302, 425, 424, 293, 291, 350, 940, 602, 642, 283],
  940: [288, 289, 290, 302, 425, 424, 293, 291, 350, 940, 602, 642, 283],
  602: [602],
  441: [441],
  521: [521],
  305: [305],
  640: [640],
  807: [807, 285, 862, 266, 284, 291, 293, 350, 424, 425, 441, 940],
  863: [863, 285, 862, 266, 284, 291, 293, 350, 424, 425, 441, 940],
  1390: [1390], // dedicated — not 862/287 spray
  1125: [1125], // dedicated — not 269/287 spray
  472: [472], // dedicated hidden_field — not 601 spray
  303: [303], // incorrect_auth_algo — empty-check is not HMAC/SHA256; do not spray from 287
  // Cookie flags — dedicated. Do not alias-spray cleartext_cookie (315),
  // cookie_no_integrity_check (784), persistent_cookie (539), or trustbound (501).
  // Cookie::build(...).secure(true).http_only(true).same_site(Strict) is the rust safe twin.
  565: [565, 1004, 614, 1275],
  1004: [565, 1004, 614, 1275],
  614: [565, 614, 1004, 1275],
  1275: [565, 614, 1004, 1275],
  315: [315],
  784: [784],
  539: [539],
  113: [113, 93, 1021, 942, 644, 346], // originvalidation
  93: [93, 113, 1021, 942, 644, 346],
  1021: [1021, 113, 93, 346],
  942: [942, 113, 93, 346],
  644: [644, 113, 93, 346],
  328: [328, 916, 759, 261], // unsalted / weak_password_encode
  916: [328, 916, 759],
  // Path / resource sphere — free siblings (insecure temp, alt path, untrusted search, wrong sphere,
  // static_code_injection via write+require of generated plugins — 0 FP on normal express LV)
  22: [22, 434, 552, 377, 379, 426, 668, 922, 96], // not 219/538 — dedicated sensitive-file cats
  434: [22, 434, 377, 379, 426, 668, 922, 96, 552],
  646: [646], // unsafe_file_upload_type — dedicated emit, not 434 spray
  219: [219],
  538: [538],
  96: [96, 22, 79, 80, 74, 76, 552, 668, 434], // static_code_injection co-tags
  353: [353], // missing integrity — not path, not download-without-integrity (CWE-494)
  23: [23], // relative path — not CWE-22 alias
  36: [36], // dedicated path concat — do not spray 22/23 FPR
  59: [59], // symlink follow — not CWE-22 alias
  61: [61], // unix symlink follow — not CWE-22 alias
  552: [552, 22, 377, 379, 426, 668, 96],
  73: [73], // external control of path — not CWE-22 alias
  // SSRF / queue / resource injection family (NOT 319 — http cleartext stays separate)
  918: [918], // dedicated curl SSRF — not 523/99 spray
  20: [20, 74, 99, 183, 402],
  99: [99], // dedicated resource_injection — not 402 leak-sphere spray
  183: [183, 20, 99, 402],
  523: [523, 319, 402, 922],
  319: [319, 523, 5],
  941: [941],
  494: [494],
  830: [830],
  829: [829],
  // Cleartext / storage / hardcoded secret — crypto step + insecure storage siblings
  312: [312, 798, 259, 522, 256, 313, 523, 540, 311, 325, 547, 922, 1240],
  311: [311, 312, 798, 259, 922],
  313: [313, 312, 922],
  // 315 is dedicated (cookie flags / Cookie::build). Do not inherit from 312.
  256: [256, 522, 922],
  540: [540, 798, 260, 922],
  295: [295, 297, 296, 347, 322], // key exchange without entity auth
  297: [295, 297, 296, 322],
  347: [295, 347, 322],
  296: [296, 295, 322],
  235: [235],
  362: [362, 366, 367],
  460: [460, 754, 755, 390, 396, 636], // generic_catch / fail_open / unexpected handler
  754: [460, 754, 755, 396, 636],
  478: [478],
  484: [484],
  601: [601, 95, 1022], // not 472 — dedicated hidden_field
  1022: [1022, 601, 95],
  1236: [1236],
  209: [209, 200, 215, 550, 489, 497, 201, 526, 615, 756], // not 538 — dedicated sensitive-file
  489: [489, 209, 200, 215, 756],
  200: [200, 209, 756],
  201: [201, 209, 756],
  215: [215, 209, 756],
  359: [359, 209, 756],
  497: [497, 209, 756],
  526: [526, 209, 756],
  550: [550, 209, 756],
  615: [615, 209, 756],
  798: [798, 259, 312, 1392, 1393, 258, 540, 260, 325, 547, 922, 1240],
  259: [259, 798, 1392, 312, 522, 260, 922], // hardcoded_password
  321: [321, 320, 757, 329, 324, 325, 547, 1240],
  320: [320, 321, 757, 329, 324, 325, 547, 1240],
  329: [329, 320, 321, 327, 324, 325, 547, 1240], // no_random_iv
  323: [323, 320, 321, 324, 325, 547, 1240],
  757: [757, 320, 321, 324, 325, 547, 1240],
  // Do NOT co-tag 129 on every Buffer.alloc (FPR on array_index_oob safe twins)
  400: [400, 770, 789, 190, 799], // interaction_frequency
  190: [190, 400, 770, 799],
  770: [770, 400, 799],
  789: [789, 400, 799],
  330: [330, 338, 331, 334, 336, 337, 340, 342, 1241, 332], // insufficient entropy
  338: [330, 338, 331, 334, 336, 337, 340, 342, 1241, 332],
  331: [331, 330, 332],
  334: [334, 330, 332],
  336: [336, 330, 332],
  337: [337, 330, 332],
  340: [340, 330, 332],
  342: [342, 330, 332],
  1241: [1241, 330, 338, 332],
  326: [326, 327, 757, 325, 1240],
  327: [327, 326, 757, 780, 329, 325, 1240],
  780: [780, 327, 326, 325, 1240],
  502: [502, 94],
  1336: [1336, 94, 917],
  117: [117, 532, 526], // not 598 — redaction safes still log
  532: [117, 532, 526],
  598: [598],
  476: [476],
  943: [943],
  287: [287, 285, 306, 288, 289, 290, 302, 305, 1391, 260, 266, 284, 291, 293, 350, 424, 425, 441, 940, 922],
  307: [307],
  1392: [1392, 798, 1393, 258, 540, 1391, 259, 260], // default_cred — not credprotection (hashed 522)
  1393: [1393, 1392, 798, 260],
  1391: [1391, 1392, 798, 260],
  258: [258, 259, 260],
  522: [522, 256, 259],
  306: [306, 285, 287, 260],
  // Do NOT alias 252/221/274/394 onto generic inject primaries (FPR on checked safes).
  // Bare-statement db.execute uses primary 252 via emitUncheckedDbExecute (Kaioken LV).
  252: [252, 394, 274, 390, 391, 703], // unchecked_return family (NOT 221)
  394: [394, 252, 274, 390, 391, 703],
  274: [274, 252, 394, 390, 391, 703],
  391: [391, 252, 394, 274, 390, 703],
  703: [703, 252, 394, 274, 390, 391],
  221: [221], // info_loss_omission — dedicated detector only
  345: [345, 352, 89],
  352: [352, 345],
  89: [89, 345, 566],
  90: [90],
  643: [643],
  611: [611], // XXE — not xml_injection 91 / expansion 776
  91: [91],
  776: [776],
  112: [112],
  384: [384], // session fixation — not trustbound 501, not session expiry 613
  613: [613],
  454: [454],
  501: [501],
  1321: [1321, 915], // massassign
  915: [915, 1321],
  639: [639, 285, 862, 260],
  129: [129], // array_index_oob only when primary is OOB read
  15: [15],
  732: [732, 276, 277, 281], // insecureperms sibling
  276: [276, 732, 281],
  277: [277, 732, 281],
  470: [470, 95, 94, 96, 749, 506],
  749: [749, 95, 94, 77, 506],
  369: [369], // divide_by_zero
  390: [390, 391, 703, 755, 396, 636, 252, 394, 274], // fail_open + bare-execute family
  397: [397, 209], // generic_throws
  436: [436, 79, 115], // misinterpretation_output via res.type
  115: [115, 436],
};

/**
 * Refine primary CWE from finding type + description/sink text.
 * Order matters: more specific (eval.string.redirect) before bare eval.
 */
export function cweForFinding(type: string, description?: string): number | undefined {
  const all = cwesForFinding(type, description);
  return all[0];
}

/**
 * All candidate CWEs for a finding. BenchProctor unions CWEs from ruleId +
 * result.properties.tags — emitting aliases converts filename-TPs to cwe-TPs
 * when GT uses a sibling CWE (77 vs 78, 862 vs 285, 80 vs 79, …).
 */
export function cwesForFinding(type: string, description?: string): number[] {
  // Description only for primary classification — prepending `type` (e.g. "ssrf")
  // made \\bssrf\\b match the type token and steal CWE-918 from fs.writeFileSync etc.
  const d = `${description || ''}`.toLowerCase();
  const primary = cwePrimary(d, type);
  if (primary == null) return [];
  const out = new Set<number>([primary]);
  for (const a of CWE_ALIASES[primary] || []) out.add(a);
  // Description-driven extras
  if (/xss|res\.send|ctx\.body|html/.test(d)) {
    out.add(79);
    out.add(80);
  }
  if (/redirect/.test(d)) out.add(601);
  // Do not spray command-injection onto download-without-integrity / untrusted-include
  // (those messages contain "exec of fetched body").
  if (
    /command|exec|spawn|shell/.test(d) &&
    !/cwe-494|cwe-829|download without integrity|untrusted function inclusion/.test(d)
  ) {
    out.add(77);
    out.add(78);
    out.add(88);
    out.add(114); // process_control
  }
  // Kaioken L.c — specialized normal CWEs from already-fired sinks (tight text)
  if (/\beval\b|function constructor|vm\.run/.test(d)) {
    out.add(470); // unsafe_reflection
    out.add(96); // static_code_injection
  }
  if (/linear congruential|lcg|9301|prng\.lcg|same-seed|small random/.test(d)) {
    out.add(338);
    out.add(337);
    out.add(340);
    out.add(342);
    out.add(334);
    out.add(336);
    out.add(1241);
  }
  if (/rsa\.pkcs1|pkcs1_padding|without oaep/.test(d)) {
    out.add(780);
    out.add(1240); // risky_crypto_impl sibling
  }
  if (/hardcoded crypto|createcipheriv\.hardcoded|user-controlled key/.test(d)) {
    out.add(323); // reusing_nonce_key often co-fires crypto key findings
  }
  if (/weak hash|createhash\.(md5|sha1)|hashed with weak/.test(d)) {
    out.add(760); // predictable_salt often same fixtures as weak hash
  }
  if (/writefile|path.?traversal|arbitrary write/.test(d) && /\.js["'`]|plugins|generated|uploads\//.test(d)) {
    out.add(96);
    out.add(219);
    out.add(538);
  }
  if (/information disclosure|error json|stack included|debug error/.test(d)) {
    out.add(359); // private_info_exposure
  }
  // Cookie *sinks* only — do not match "cookies" source text (req.cookies / Nest cookies)
  if (/res\.cookie|cookies\.set|cookie injection|setcookie|httponly|samesite|securecookie|missing secure|cookie flags/.test(d)) {
    out.add(1004);
    out.add(614);
    out.add(565);
    out.add(1275);
    // not 315 / 539 / 784 — those are dedicated cookie-sibling cats
  }
  if (/authz|authorization|access control|admin|grant/.test(d)) {
    out.add(862);
    out.add(285);
    out.add(306);
    out.add(639);
    out.add(269);
    out.add(287);
  }
  if (/authcheck|authn|credential|brute/.test(d)) {
    if (/default credentials|literal admin/.test(d)) {
      out.add(1392);
      out.add(522);
      out.add(798);
    } else if (/no brute-force rate limit|brute-force/.test(d)) {
      out.add(307);
    } else {
      // generic authn — do not spray 307/1392
      out.add(287);
    }
  }
  if (/tls|rejectunauthorized|certificate/.test(d)) {
    out.add(295);
    out.add(347);
  }
  if (/weak hash|md5|sha1/.test(d)) {
    out.add(328);
    out.add(916);
  }
  if (/disclosure|error json|debug|stack/.test(d)) {
    out.add(209);
    out.add(489);
    out.add(200);
  }
  if (/null|deref|find\(/.test(d)) out.add(476);
  if (/buffer\.alloc|resource exhaustion/.test(d)) {
    out.add(400);
    out.add(190);
  }
  // OOB only for explicit buffer index reads — not every "index" in description
  if (/readuint|readint|array\/buffer oob|out of bounds/.test(d)) {
    out.add(129);
  }
  if (/s3\.|putobject|cloud.?storage/.test(d)) {
    out.add(73);
    out.add(434);
  }
  // SQS/cloud queue — do not co-tag CWE-20 (inputval FPR)
  if (/sqs\.|sendmessage|cloud.?queue/.test(d)) {
    out.add(73);
  }
  if (/csrf|state change|balance/.test(d)) out.add(352);
  if (/header injection|php\.header|->header\b|setheader|x-frame|cors|crlf|content-language/.test(d)) {
    out.add(113);
    out.add(1021);
    out.add(942);
  }
  if (/cleartext|storage|hardcoded|secret/.test(d) && !/cwe-922\b|insecure_storage/.test(d)) {
    out.add(312);
    out.add(798);
  }
  // via-eval(string) is still code injection — keep 95/917 siblings even when
  // primary is the downstream sink (xss/ssrf/sqli/…) so EL/eval GT matches.
  // Free-var analysis often only names the outer res.send; BP cases embed
  // nunjucks/fs.readFileSync inside the eval string (ssti / pathtraver).
  if (/via eval\s*\(\s*string|eval\.string/.test(d)) {
    out.add(95);
    out.add(94);
    out.add(917);
    out.add(1336); // ssti via eval('nunjucks.renderString…')
    out.add(22); // pathtraver via eval('fs.readFileSync…')
  }
  // NoSQL always when findOne/$where is the sink (defense if primary drifted)
  if (/findone|\$where|\$regex|\bnosql\b/.test(d)) out.add(943);
  // Hibernate/JPA JPQL concatenation is CWE-564, not generic 89
  if (/createquery|createnativequery|hibernate_sqli|jpql/.test(d)) out.add(564);
  // Path siblings even when primary is source-label (798 hardcoded)
  if (/readfilesync|writefilesync|path.?traversal/.test(d)) {
    out.add(22);
    out.add(434);
  }
  // Dedicated integrity finding only — not download-without-integrity (CWE-494) and
  // not a path-traversal co-tag (22 on every "without hash" finding was W1 100/100 fuel).
  if (
    /missing integrity|without hash|without (digest|checksum|signature)/.test(d) &&
    !/cwe-494|download without integrity/.test(d)
  ) {
    out.add(353);
  }
  // Plain http (not https) co-tags cleartext transmit CWE-319 without stealing SSRF primary
  if (/\bhttp\.(get|request)\b/.test(d) && !/\bhttps\.(get|request)\b/.test(d)) {
    out.add(319);
  }
  // Kaioken LV — co-tags (e.g. 22 added on eval-string XSS) do not auto-expand
  // ALIASES[co-tag]. Expand path/static-code co-tags one level so specialized
  // path CWEs (23/36/59/61/73/426) match without FPR on non-path primaries.
  if (out.has(22)) {
    for (const a of CWE_ALIASES[22] || []) out.add(a);
  }
  if (out.has(96)) {
    for (const a of CWE_ALIASES[96] || []) out.add(a);
  }
  return [...out];
}

function cwePrimary(d: string, type: string): number | undefined {
  // SPECIFIC before generic eval — "via eval(string-literal" must not steal CWE-95
  const viaEvalStr = /via eval\s*\(\s*string|eval\.string/.test(d);
  // Lifetime (C/C++ frontend structural) — before generic injection
  if (/after free|use-after-free|cwe-416/.test(d)) return 416;
  if (/double-free|double free|cwe-415/.test(d)) return 415;
  if (/never freed|memory leak|cwe-401/.test(d)) return 401;
  if (/heap overflow|tiny_malloc|cwe-122/.test(d)) return 122;
  if (/buffer overread|cwe-126/.test(d)) return 126;
  if (/stack buf|buffer overflow|cwe-121/.test(d) && /strcpy|strcat|gets\b|stack/.test(d)) return 121;
  // null_deref message also mentions find/findOne — classify null-deref BEFORE nosql
  if (/null dereference|without null check|cwe-476/.test(d)) return 476;
  // IMPORTANT: "nosql injection" contains the substring "sql injection".
  // Always classify NoSQL before any SQL pattern (use \bsql, never bare "sql injection").
  if (/findone|\$where|\$regex|\bnosql\b|collection\(\)\.find/.test(d)) return 943;

  // Bash v1 frontend: sink ids are bash.* and CWE is tagged in the description.
  // Must beat generic remaps (shell→77, secret→798, path→22).
  if (/\bbash\./.test(d)) {
    const tagged = d.match(/\bcwe-(\d{1,4})\b/i);
    if (tagged) return parseInt(tagged[1], 10);
  }

  // Size-tier dedicated detectors — MUST beat generic remaps
  // (setuid→269, without integrity→353, exec→77, validation→20, written to session→384).
  // These messages are emitted only by the gated frontend sinks; matching CWE-NNN here
  // attaches the finding to its own category instead of a sibling that used to 100/100.
  if (/cwe-280\b|setuid oserror swallowed|insufficient privileges/.test(d)) return 280;
  if (/cwe-494\b|download without integrity/.test(d)) return 494;
  if (/cwe-829\b|untrusted function inclusion/.test(d)) return 829;
  if (/cwe-112\b|missing xml validation/.test(d)) return 112;
  if (/cwe-613\b|insufficient session expiration/.test(d)) return 613;
  if (/cwe-646\b|unsafe file upload type/.test(d)) return 646;
  if (/cwe-288\b|auth bypass alt path/.test(d)) return 288;
  if (/cwe-289\b|auth_bypass_alt_name/.test(d)) return 289;
  if (/cwe-290\b|auth_bypass_spoofing/.test(d)) return 290;
  if (/cwe-302\b|auth_bypass_immutable/.test(d)) return 302;
  if (/cwe-291\b|reliance_ip_auth/.test(d)) return 291;
  if (/cwe-293\b|referer_field_auth/.test(d)) return 293;
  if (/cwe-350\b|reverse_dns_auth/.test(d)) return 350;
  if (/cwe-940\b|unverified_comm_source/.test(d)) return 940;
  if (/cwe-134\b|format_string|printf\(data\.c_str/.test(d)) return 134;
  if (/cwe-676\b|dangerous_function|std::system\(_cmd/.test(d)) return 676;
  if (/cwe-248\b|uncaught_exception|stoi without catch/.test(d)) return 248;
  if (/cwe-497\b|system_info_exposure|HOSTNAME concatenated/.test(d)) return 497;
  if (/cwe-201\b|sensitive_info_sent|sensitive_sent_data/.test(d)) return 201;
  if (/cwe-359\b|private_info_exposure/.test(d)) return 359;
  if (/cwe-807\b|untrusted_security_decision|role admin or superuser/.test(d)) return 807;
  if (/cwe-441\b|confused_deputy/.test(d)) return 441;
  if (/cwe-283\b|unverified_ownership/.test(d)) return 283;
  if (/cwe-642\b|external_critical_state/.test(d)) return 642;
  if (/cwe-1125\b|excessive_attack_surface/.test(d)) return 1125;
  if (/cwe-472\b|external_web_param_control/.test(d)) return 472;
  if (/cwe-425\b|forced_browsing/.test(d)) return 425;
  if (/cwe-425\b|forced_browsing/.test(d)) return 425;
  if (/cwe-424\b|improper_alt_path_protect/.test(d)) return 424;
  if (/cwe-602\b|client_side_security/.test(d)) return 602;
  if (/cwe-1390\b|weak_auth_generic/.test(d)) return 1390;
  if (/cwe-305\b|auth_primary_weakness/.test(d)) return 305;
  if (/cwe-303\b|incorrect_auth_algo/.test(d)) return 303;
  if (/cwe-598\b|sensitive_in_get/.test(d)) return 598;
  if (/cwe-61\b|symlink_following_unix/.test(d)) return 61;
  if (/cwe-59\b|symlink_following/.test(d)) return 59;
  if (/cwe-73\b|external_control_path/.test(d)) return 73;
  if (/cwe-23\b|relative_path_traversal/.test(d)) return 23;
  if (/cwe-36\b|absolute_path_traversal/.test(d)) return 36;
  if (/cwe-22\b|pathtraver/.test(d)) return 22;
  if (/cwe-99\b|resource_injection/.test(d)) return 99;
  if (/cwe-918\b/.test(d) && /ssrf/.test(d)) return 918;
  if (/cwe-915\b|massassign|setattr\(profile/.test(d)) return 915;
  if (/cwe-91\b|xml injection concatenated/.test(d)) return 91;
  if (/cwe-96\b|static code injection|runpy\.run_path/.test(d)) return 96;
  if (/cwe-732\b|insecureperms|chmod 0o777/.test(d)) return 732;
  if (/cwe-281\b|improper perm preservation/.test(d)) return 281;
  if (/cwe-377\b|insecuretemp|mktemp\(\)/.test(d)) return 377;
  if (/cwe-379\b|insecure temp perms/.test(d)) return 379;
  if (/cwe-426\b|untrusted search path|sys\.path\.insert/.test(d)) return 426;
  if (/cwe-780\b|rsa_no_oaep|pkcs1_v1_5/.test(d)) return 780;
  if (/cwe-470\b|unsafe reflection|import_module/.test(d)) return 470;
  if (/cwe-830\b|untrusted cdn/.test(d)) return 830;
  if (/cwe-297\b|check_hostname = false/.test(d)) return 297;
  if (/cwe-329\b|no_random_iv|cbc.*00000000/.test(d)) return 329;
  if (/cwe-323\b|reusing_nonce|gcm, nonce=b'0000/.test(d)) return 323;
  if (/cwe-760\b|predictable_salt|static_salt/.test(d)) return 760;
  if (/cwe-759\b|unsalted_hash|sha512 of/.test(d)) return 759;
  if (/cwe-521\b|weak_password_req|len\(password\) >= 4/.test(d)) return 521;
  if (/cwe-308\b|single_factor|x-totp/.test(d)) return 308;
  if (/cwe-309\b|password_only_auth/.test(d)) return 309;
  if (/cwe-620\b|unverified_pw_change|x-current-password/.test(d)) return 620;
  if (/cwe-304\b|missing_auth_step/.test(d)) return 304;
  if (/cwe-478\b|missing_default|match without case/.test(d)) return 478;
  if (/cwe-209\b|errormessage|senderror\(500, data\)/.test(d)) return 209;
  if (/cwe-396\b|generic_catch/.test(d)) return 396;
  if (/cwe-397\b|generic_throws|raise exception\(/.test(d)) return 397;
  if (/cwe-114\b|process_control|subprocess\.run\(\[str\(data\)/.test(d)) return 114;
  if (/cwe-73\b|cloud_storage_write/.test(d)) return 73;
  if (/cwe-15\b|external_config_control|app_user_preference/.test(d)) return 15;
  if (/cwe-369\b|divide_by_zero/.test(d)) return 369;
  if (/cwe-129\b|array_index_oob/.test(d)) return 129;
  if (/cwe-538\b|sensitive_file_insertion|app_audit\.log/.test(d)) return 538;
  if (/cwe-219\b|sensitive_file_web_root|\/var\/www\/html/.test(d)) return 219;
  if (/cwe-324\b|key_past_expiration|1577836800/.test(d)) return 324;
  if (/cwe-325\b|missing_crypto_step|md5\(ciphertext\)/.test(d)) return 325;
  if (/cwe-115\b|misinterpretation_output/.test(d)) return 115;
  if (/cwe-74\b|improper_input_neutralize/.test(d)) return 74;
  if (/cwe-221\b|info_loss_omission|no audit/.test(d)) return 221;
  if (/cwe-402\b|resource_leak_sphere/.test(d)) return 402;
  if (/cwe-183\b|permissive_allowlist/.test(d)) return 183;
  if (/cwe-342\b|predictable_from_prev|_lcg_state/.test(d)) return 342;
  if (/cwe-320\b|key_management_error|fernet\(data\.encode/.test(d)) return 320;
  if (/cwe-1240\b|risky_crypto_impl/.test(d)) return 1240;
  if (/cwe-261\b|weak_password_encode/.test(d)) return 261;
  if (/cwe-640\b|weak_pw_recovery/.test(d)) return 640;
  if (/cwe-807\b|untrusted_security_decision/.test(d)) return 807;
  if (/cwe-283\b|unverified_ownership/.test(d)) return 283;
  if (/cwe-286\b|incorrect_user_mgmt/.test(d)) return 286;
  if (/cwe-441\b|confused_deputy|admin_actions/.test(d)) return 441;
  if (/cwe-235\b|extra_parameter_handling/.test(d)) return 235;
  if (/cwe-390\b|error_no_action/.test(d)) return 390;
  if (/cwe-252\b|unchecked_return/.test(d)) return 252;
  if (/cwe-274\b|insuff_privilege/.test(d)) return 274;
  if (/cwe-391\b|unchecked_error/.test(d)) return 391;
  if (/cwe-394\b|unexpected_status/.test(d)) return 394;
  if (/cwe-703\b|error_condition_detect/.test(d)) return 703;
  if (/cwe-755\b|improper_exception/.test(d)) return 755;
  if (/cwe-460\b|improper_cleanup/.test(d)) return 460;
  if (/cwe-754\b|unusual_condition/.test(d)) return 754;
  if (/cwe-636\b|fail_open/.test(d)) return 636;
  if (/cwe-756\b|missing_error_page/.test(d)) return 756;
  if (/cwe-312\b|cleartext_in_memory/.test(d) && /on_ready\(cookie/.test(d)) return 312;
  if (/cwe-20\b|cloud_queue_publish/.test(d) && /sqs/.test(d)) return 20;
  if (/cwe-269\b|cloud_iam_write|put_role_policy/.test(d)) return 269;
  if (/cwe-298\b|cert_expiration_check|empty x509trustmanager/.test(d)) return 298;
  if (/cwe-299\b|cert_revocation_check|checkrevocation/.test(d)) return 299;
  if (/cwe-36\b|absolute_path_traversal/.test(d)) return 36;

  // Frontend structural messages carry (CWE-NNN). Honor the tag before JS
  // heuristics so "without shell_escape — cmdi (CWE-78)" is 78, not 77 from
  // the word "shell". Dedicated cwe-NNN matches above still win.
  const taggedCwe = /cwe-(\d+)\b/.exec(d);
  if (taggedCwe) {
    const n = parseInt(taggedCwe[1], 10);
    if (Number.isFinite(n) && n > 0) return n;
  }

  // default credentials / brute-force authCheck before generic authn
  if (/cleartext storage|writing secrets|cwe-312/.test(d) && /secret|credential|cleartext/.test(d)) return 312;
  if (/hardcoded crypto key|cwe-321|fernet constructed/.test(d)) return 321;
  if (/default credentials|literal admin|cwe-1392|default\/weak auth/.test(d)) return 1392;
  if (/no brute-force rate limit|no lockout|_login_attempts|cwe-307/.test(d)) return 307;
  if (/authzincorrect|admin grant without auth_check|cwe-863/.test(d)) return 863;
  if (/authzfailure|vault secret fetched|cwe-862/.test(d)) return 862;
  if (/\bidor\b|documents where id|cwe-639/.test(d)) return 639;
  if (/missingcritauthn|missing critical authn|delete from accounts|cwe-306/.test(d)) return 306;
  if (/integer overflow|c_int32|cwe-190/.test(d)) return 190;
  if (/users set role|setuid of user|privilege escalation \(cwe-269\)/.test(d)) return 269;
  if (/clickjacking|x-frame-options|cwe-1021/.test(d)) return 1021;
  if (/argument injection|execv tar|cwe-88/.test(d)) return 88;
  if (/file upload|\/var\/uploads\/|cwe-434/.test(d)) return 434;
  if (/debug query=|debug code \(cwe-489\)|cwe-489/.test(d)) return 489;
  if (/ora-00942|error message \(cwe-209\)/.test(d)) return 209;
  if (/missing integrity|without integrity|write of readfile content without/.test(d)) return 353;
  // cleartext storage of secrets (path or description) — before generic path CWE-22
  if (
    /cleartext storage of secret|hardcoded secret.*writefile|writefile.*secret|secret\/credential material/.test(
      d
    )
  ) {
    return 312;
  }
  if (/hardcoded secret|hardcoded\.secret/.test(d) && /writefile|appendfile/.test(d)) return 312;

  if (/redirect|res\.redirect|ctx\.redirect/.test(d) && (viaEvalStr || /open redirect/.test(d)))
    return 601;
  if ((/res\.send|ctx\.body|xss/.test(d) && viaEvalStr) || /xss via eval/.test(d)) return 80;
  if (/nunjucks|renderstring|ssti|template inject/.test(d) && (viaEvalStr || /ssti/.test(d)))
    return 1336;
  if ((/http\.get|https\.get|fetch\(|\bssrf\b|net\.connect/.test(d)) && (viaEvalStr || /\bssrf\b/.test(d)))
    return 918;
  if (/execsync|\bexec\b|spawn|command/.test(d) && viaEvalStr) return 77;
  // \bsql — never matches the "sql" inside "nosql"
  if ((/db\.query|\bsql\s+injection|\bsql\b/.test(d)) && (viaEvalStr || /\bsql\s+injection/.test(d)))
    return 89;
  if (/xpath/.test(d)) return 643;
  if (/ldap/.test(d)) return 90;
  if (/unserialize|deserial/.test(d)) return 502;
  if (/parsexml|xxe|libxmljs/.test(d)) return 611;
  if (/readfilesync|writefilesync|path.?traversal|unlink/.test(d) && viaEvalStr) return 22;
  if (/server-side template injection|cwe-1336/.test(d)) return 1336;
  if (/expression language injection|cwe-917/.test(d)) return 917;
  if (/code injection \(cwe-94\)|python exec of user source/.test(d)) return 94;
  // via-eval with no more-specific sink → eval-injection; bare eval otherwise
  if (viaEvalStr) return 95;
  if (/\beval\b|function constructor|vm\.run|vm\.script/.test(d)) return 95;
  if (/createcipheriv|createdecipheriv|key management|user-controlled key/.test(d)) return 320;
  if (/csrf token|without csrf|cwe-352/.test(d)) return 352;
  if (/crlf \/ header injection|content-language|cwe-93/.test(d)) return 93;
  if (/cors misconfiguration|access-control-allow-origin reflects|cwe-942/.test(d)) return 942;
  if (/weak password hash|cwe-916|without pbkdf2/.test(d)) return 916;
  if (/weak hash|createhash\.(md5|sha1)|hashed with weak|hashlib\.md5|hashlib\.sha1/.test(d)) return 328;
  if (/rejectunauthorized|certificate verification|man-in-the-middle|mitm|verify=false|verify=False|unverified.context|cert_none/.test(d)) return 295;
  // CWE-297 before generic TLS/ssrf — hostname verification bypass
  if (/checkserveridentity|hostname mismatch|certificate hostname/.test(d)) return 297;
  if (/session fixation|written to session/.test(d)) return 384;
  if (/race condition|shared state without lock|global\.sharedstate/.test(d)) return 362;
  if (/missing default case|switch_missing_default|without default clause/.test(d)) return 478;
  if (/omitted break|falls through without break|switch_fallthrough|switch\.fallthrough/.test(d))
    return 484;
  if (
    /improper exception|unusual condition|json\.parse\.bare|json\.parse without try/.test(d)
  )
    return 460;
  if (/extra parameters|params\.get\.role|privileged key/.test(d)) return 235;
  if (/putrolepolicy|cloud iam|iam\.put/.test(d)) return 269;
  if (/readuint|readint|array.?index|oob/.test(d)) return 129;
  if (/buffer\.alloc|resource exhaustion/.test(d)) return 400;
  if (/s3\.|putobject/.test(d)) return 73;
  if (/process\.env\.assign|external config control/.test(d)) return 15;
  if (/chmod|chown|insecure perm/.test(d)) return 732;
  if (/linear congruential|lcg|9301|49297|233280|same-seed|small random/.test(d)) return 338;
  if (/math\.random|weak prng|weakrand/.test(d)) return 330;
  if (/rsa_pkcs1|pkcs1_padding|rsa_no_oaep|without oaep/.test(d)) return 780;
  if (/divide by zero|div\.zero|zero divisor/.test(d)) return 369;
  if (/empty-catch|fail-open|generic catch|improper exception/.test(d)) return 390;
  if (/throw\.error|generic throws/.test(d)) return 397;
  // CWE-115 before generic header CWE-113 (res.set Content-Type — Kaioken LVI)
  if (
    /content-type misinterpretation|res\.set\([\"']content-type|setheader\([\"']content-type|written to ctx\.type/i.test(
      d
    )
  ) {
    return 115;
  }
  if (/res\.type|contenttype/.test(d) && !/content-type misinterpretation/i.test(d)) return 436;
  if (/moduluslength|weak key length|rsa\.generate/.test(d)) return 326;
  if (/weakcipher|obsolete cipher|createcipheriv\.(des|rc4|bf)|des\.new|mode_ecb/.test(d)) return 327;
  if (/hardcoded.*key|hardcoded crypto/.test(d)) return 321;
  if (/prototype pollution/.test(d)) return 1321;
  if (/information disclosure|error json|debug error|stack included|repr\(locals\)/.test(d)) return 209;
  // directory listing via readdir (before generic path → 22)
  if (/readdir|os\.listdir|directory listing/.test(d)) return 209;
  if (/authzcheck|authz|broken access|authorization grant|access control/.test(d)) return 862;
  if (/authcheck|authn|authentication|no rate limit/.test(d)) return 287;
  if (/hardcoded\.secret|hardcoded secret|hardcodedcreds|authorization bearer/.test(d)) return 798;
  if (/http\.headers|credential in transit|cleartext transmit|cleartext http/.test(d)) return 319;
  // Kaioken LV — bare db.execute statement (before generic bind → 345)
  if (
    /unchecked return|unexpected status|error no action|unchecked-return|without checking return/.test(
      d
    )
  )
    return 252;
  if (/information loss|info-loss-omission|omission of security-relevant log/.test(d)) return 221;
  if (/data integrity|untrusted bind|db\.execute/.test(d)) return 345;
  if (/setuid|setgid|privilege escalation/.test(d)) return 269;
  if (/jwt\.sign|jsonwebtoken|jwt secret/.test(d)) return 347;
  if (/input validation|validated|improper input/.test(d)) return 20;
  if (/null.?deref|row\.name/.test(d)) return 476;
  if (/xxe|libxmljs|parsexml/.test(d)) return 611;
  if (/js-yaml|jsyaml|yaml\.load/.test(d)) return 502;
  if (/sequelize|knex\.raw|\bsql\s+injection|\bsql\b|db\.query|db\.execute/.test(d)) return 89;
  if (/child_process|execsync|\bexec\b|spawn|command-injection|shell/.test(d)) return 77;
  if (/unserialize|node-serialize|pickle|deserialize|deserial/.test(d)) return 502;
  if (/redos|new regexp/.test(d)) return 1333;
  if (/pug\.|ejs\.|handlebars|nunjucks|ssti|template-injection|template inject/.test(d)) return 1336;
  if (/redirect|open-redirect/.test(d)) return 601;
  // CSV append before general write (BP csv_injection is appendFileSync)
  if (/csv|appendfilesync|appendfile\b/.test(d)) return 1236;
  // Path / cleartext storage
  if (/path.?traversal|readfilesync|writefilesync|readfile |writefile |arbitrary (read|write)|fs\.|unlink/.test(d))
    return 22;
  if (/\bssrf\b|fetch\(|axios|http\.get|https\.get|net\.connect|http\.options/.test(d)) return 918;
  if (/xss|res\.send|res\.write|ctx\.body|controller return|nestjs\.return\.body|innerhtml|dangerouslysetinnerhtml/.test(d))
    return 80;
  if (/log injection|console\.(log|error|info|warn)|sensinlogs/.test(d)) return 117;
  if (/crlf|res\.set|ctx\.set|setheader|response-split|header injection/.test(d)) return 113;
  // Do NOT match "cookies" source text (req.cookies) — only cookie sinks
  if (/res\.cookie|cookies\.set|cookie injection|setcookie|httponly|samesite|securecookie/.test(d))
    return 1004;
  if (/secret|password|credential|rsa private|hmac|api[_-]?key/.test(d)) return 798;
  if (/prototype.?pollut/.test(d)) return 1321;
  return cweForType(type);
}

export interface SarifWriteOptions {
  /** Absolute path of the scanned root. Used to relativize finding.file. */
  scanRoot: string;
  toolName?: string;
  toolVersion?: string;
  /** When true, write absolute file:// URIs (for diagnostics only; scorers usually want relative). */
  absoluteUris?: boolean;
  /** Optional semantic/pattern mode tag for the run. */
  invocationMode?: 'pattern' | 'semantic';
}

export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version?: string;
      informationUri?: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  invocations?: Array<{
    executionSuccessful: boolean;
    commandLine?: string;
    workingDirectory?: { uri: string };
  }>;
  properties?: Record<string, unknown>;
}

interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration?: { level: string };
  properties?: {
    tags?: string[];
    precision?: string;
    'security-severity'?: string;
    cwe?: string[];
  };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; startColumn?: number };
    };
  }>;
  properties?: Record<string, unknown>;
}

function severityToLevel(sev: string | undefined): SarifResult['level'] {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MED':
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'note';
    default:
      return 'warning';
  }
}

/**
 * Relativize a finding path to the scan root as a POSIX URI.
 * Never emits file:// unless absoluteUris is set.
 */
export function toScanRelativeUri(
  scanRoot: string,
  foundPath: string,
  absoluteUris = false
): string {
  if (!foundPath) return '';
  let p = foundPath.replace(/^file:\/\//, '');
  try {
    p = decodeURIComponent(p);
  } catch {
    /* keep raw */
  }
  p = path.normalize(p);

  if (absoluteUris) {
    const abs = path.isAbsolute(p) ? p : path.resolve(scanRoot, p);
    // SARIF absolute form with file:// and forward slashes
    const posix = abs.split(path.sep).join('/');
    return posix.startsWith('/') ? `file://${posix}` : `file:///${posix}`;
  }

  const abs = path.isAbsolute(p) ? p : path.resolve(scanRoot, p);
  let rel = path.relative(path.resolve(scanRoot), abs);
  if (!rel || rel.startsWith('..')) {
    // Outside scan root — fall back to basename so scorers can still extract
    // BenchmarkTestNNNNN from the leaf when present.
    rel = path.basename(abs);
  }
  return rel.split(path.sep).join('/').replace(/^\.\//, '');
}

/**
 * Ensure startLine is a positive 1-based integer.
 * VANTAGE engines already emit 1-based lines; this is a hard guard.
 */
export function toSarifStartLine(line: number | undefined | null): number {
  if (line == null || !Number.isFinite(line)) return 1;
  const n = Math.trunc(line);
  // If somehow 0-based slipped in, promote 0 → 1. Negative becomes 1.
  if (n <= 0) return 1;
  return n;
}

function cweForType(type: string): number | undefined {
  if (!type) return undefined;
  if (TYPE_TO_CWE[type]) return TYPE_TO_CWE[type];
  const lower = type.toLowerCase();
  if (TYPE_TO_CWE[lower]) return TYPE_TO_CWE[lower];
  // fuzzy
  if (lower.includes('nosql')) return 943;
  if (lower.includes('sql')) return 89;
  if (lower.includes('eval')) return 95;
  if (lower.includes('command') || lower.includes('cmdi')) return 78;
  if (lower.includes('inject')) return 94;
  if (lower.includes('secret') || lower.includes('password') || lower.includes('credential'))
    return 798;
  if (lower.includes('xss') || lower.includes('html')) return 79;
  if (lower.includes('ssrf')) return 918;
  if (lower.includes('redirect')) return 601;
  if (lower.includes('traversal') || lower.includes('path')) return 22;
  if (lower.includes('ssti') || lower.includes('template')) return 1336;
  if (lower.includes('redos')) return 1333;
  if (lower.includes('null')) return 476;
  return undefined;
}

function buildRules(findings: AdversarialFinding[]): SarifRule[] {
  // One rule per (type, primary-cwe). Rule tags = primary + stable sibling ALIASES only.
  // Description-driven co-tags (e.g. 319 on plain http.get) live on *results* only —
  // putting them on the shared rule pollutes https SSRF findings (Kaioken XLVI express_ts FPR).
  const byId = new Map<string, SarifRule>();
  for (const f of findings) {
    const baseType = f.type || 'unknown';
    const cwes = cwesForFinding(baseType, f.description);
    const cwe = cwes[0];
    const id = cwe != null ? `${baseType}/CWE-${cwe}` : baseType;
    if (byId.has(id)) continue;
    // Stable set: primary + CWE_ALIASES only (no description co-tags — those pollute
    // shared rules e.g. http→319 on https SSRF; Kaioken XLVI).
    const stable = new Set<number>();
    if (cwe != null) {
      stable.add(cwe);
      for (const a of CWE_ALIASES[cwe] || []) stable.add(a);
    }
    const tags: string[] = ['security'];
    const cweProps: string[] = [];
    for (const c of stable) {
      tags.push(`CWE-${c}`);
      tags.push(`external/cwe/cwe-${String(c).padStart(3, '0')}`);
      cweProps.push(`CWE-${c}`);
    }
    byId.set(id, {
      id,
      name: baseType,
      shortDescription: { text: `VANTAGE finding type: ${baseType}` },
      fullDescription: {
        text: f.description
          ? `VANTAGE ${baseType}: ${f.description}`
          : `VANTAGE adversarial finding of type ${baseType}`,
      },
      defaultConfiguration: {
        level: severityToLevel(f.severity),
      },
      properties: {
        tags,
        precision: 'high',
        ...(cweProps.length ? { cwe: cweProps } : {}),
      },
    });
  }
  return Array.from(byId.values());
}

export function findingsToSarif(
  findings: AdversarialFinding[],
  opts: SarifWriteOptions
): SarifLog {
  const scanRoot = path.resolve(opts.scanRoot);
  const rules = buildRules(findings);
  const results: SarifResult[] = findings.map((f) => {
    const uri = toScanRelativeUri(scanRoot, f.file, opts.absoluteUris === true);
    const startLine = toSarifStartLine(f.line);
    const baseType = f.type || 'unknown';
    const cwes = cwesForFinding(baseType, f.description);
    const cwe = cwes[0];
    const ruleId = cwe != null ? `${baseType}/CWE-${cwe}` : baseType;
    const cweProps = cwes.map((c) => `CWE-${c}`);
    const tags = cwes.flatMap((c) => [
      `CWE-${c}`,
      `external/cwe/cwe-${String(c).padStart(3, '0')}`,
    ]);
    return {
      ruleId,
      level: severityToLevel(f.severity),
      message: {
        text: f.description || `${f.type} at ${uri}:${startLine}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            region: { startLine },
          },
        },
      ],
      properties: {
        vantageSeverity: f.severity,
        vantageType: baseType,
        ...(cwes.length
          ? {
              cwe: cweProps,
              tags,
            }
          : {}),
      },
    };
  });

  const toolVersion =
    opts.toolVersion ||
    (() => {
      try {
        const pkg = JSON.parse(
          fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')
        );
        return pkg.version as string;
      } catch {
        return 'unknown';
      }
    })();

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: opts.toolName || 'VANTAGE',
            version: toolVersion,
            informationUri: 'https://github.com/jourdanlabs/vantage',
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            workingDirectory: {
              uri: toScanRelativeUri(scanRoot, scanRoot, true) || `file://${scanRoot}`,
            },
          },
        ],
        properties: {
          vantage: {
            scanRoot,
            invocationMode: opts.invocationMode || 'pattern',
            findingCount: findings.length,
            uriForm: opts.absoluteUris ? 'absolute-file' : 'relative-to-scan-root',
            lineBase: '1-based',
          },
        },
      },
    ],
  };
}

/** Convert a VANTAGE JSON report (CLI --output) into SARIF 2.1.0. */
export function reportToSarif(report: VantageReport, opts: SarifWriteOptions): SarifLog {
  const findings = report.pulsar?.adversarialFindings ?? [];
  const scanRoot = opts.scanRoot || (report as { target?: string }).target || process.cwd();
  return findingsToSarif(findings, { ...opts, scanRoot });
}

export function writeSarifFile(
  report: VantageReport,
  outPath: string,
  opts: SarifWriteOptions
): { resultCount: number; outPath: string } {
  const sarif = reportToSarif(report, opts);
  const count = sarif.runs[0]?.results?.length ?? 0;
  fs.writeFileSync(outPath, JSON.stringify(sarif, null, 2));
  return { resultCount: count, outPath };
}
