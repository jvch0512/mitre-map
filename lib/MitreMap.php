<?php
declare(strict_types=1);

namespace MitreMap;

require_once __DIR__ . '/AttackData.php';

const RANK = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
const MAX_BYTES = 20000000;
const EXTENSIONS = ['yml', 'yaml', 'yar', 'yara', 'md', 'txt', 'csv', 'tsv', 'json'];

function rank(string $sev): int
{
    return RANK[$sev] ?? 4;
}

/** Enterprise tactics of the bundled ATT&CK release: tag name (as Sigma writes it, with hyphens) => display name. */
function tactics(): array
{
    $t = [];
    foreach (ATTACK_TACTICS as $short => [$id, $name]) {
        $t[$short] = $name;
    }
    return $t;
}

/** Turns a tag spelling into the canonical shortname: Sigma used underscores before it moved to hyphens. */
function tactic_key(string $v): string
{
    return str_replace('_', '-', strtolower($v));
}

/** Technique id => tactics it belongs to, for current Enterprise techniques. Used for coverage only. */
function catalogue(): array
{
    static $c = null;
    if ($c === null) {
        $c = [];
        foreach (ATTACK_TECHNIQUES as $id => [$name, $tac, $status, $by, $dom]) {
            if ($dom === 0 && $status === 'active') {
                $c[$id] = $tac;
            }
        }
    }
    return $c;
}

/** Retired technique ids (revoked or deprecated) => replacement id or null when ATT&CK names none. */
function deprecated(): array
{
    static $d = null;
    if ($d === null) {
        $d = [];
        foreach (ATTACK_TECHNIQUES as $id => [$name, $tac, $status, $by, $dom]) {
            if ($status !== 'active') {
                $d[$id] = $by;
            }
        }
    }
    return $d;
}

/** True when the id exists in the bundled Enterprise, ICS or Mobile release (retired ids included). */
function known_technique(string $id): bool
{
    return isset(ATTACK_TECHNIQUES[$id]);
}

function is_valid_id(string $id): bool
{
    return preg_match('/^T\d{4}(\.\d{3})?$/', $id) === 1;
}

/**
 * Finds ATT&CK references in one text.
 * Returns a list of ['line' => int, 'kind' => 'id'|'bad'|'tactic'|'other'|'unknown', 'value' => string].
 */
function extract_refs(string $text, bool $yaml): array
{
    $refs = [];
    $seen = [];
    $lines = preg_split('/\r\n|\n|\r/', $text) ?: [];
    $context = preg_match('/att&ck|mitre|technique|tactic|\bttps?\b/i', $text) === 1;
    $n = 0;
    foreach ($lines as $line) {
        $n++;
        if ($n > 2000000 || strlen($line) > 200000) {
            continue;
        }
        $add = function (string $kind, string $value) use (&$refs, &$seen, $n): void {
            $k = $n . '|' . $kind . '|' . $value;
            if (!isset($seen[$k])) {
                $seen[$k] = true;
                $refs[] = ['line' => $n, 'kind' => $kind, 'value' => $value];
            }
        };
        $tagContext = $yaml || preg_match('/tags?\s*[:=]/i', $line) === 1 || preg_match('/^\s*[-*]\s+`?attack\./i', $line) === 1;
        if ($tagContext && preg_match_all('/(?:^|[\s\[,"\'`])attack\.([A-Za-z0-9_.\-]+)(?=$|[\s\],"\'`])/i', $line, $m)) {
            foreach ($m[1] as $raw) {
                $v = strtolower($raw);
                if (preg_match('/^t\d{4}(\.\d{3})?$/', $v)) {
                    $add('id', strtoupper($v));
                } elseif (preg_match('/^t\d+(\.\d+)?$/', $v)) {
                    $add('bad', strtoupper($v));
                } elseif (preg_match('/^[gs]\d{4}$/', $v)) {
                    $add('other', strtoupper($v));
                } elseif (isset(tactics()[tactic_key($v)])) {
                    $add('tactic', tactic_key($v));
                } elseif ($v === 'defense-evasion' || $v === 'defense_evasion') {
                    $add('legacy_tactic', 'defense-evasion');
                } elseif (in_array(tactic_key($v), ATTACK_OTHER_TACTICS, true)) {
                    $add('other_tactic', tactic_key($v));
                } else {
                    $add('unknown', $raw);
                }
            }
        }
        if ($context
            && preg_match_all('/\bT\d{3,5}(?:\.\d{1,4})?\b/', $line, $m2)) {
            foreach ($m2[0] as $id) {
                $add(is_valid_id($id) ? 'id' : 'bad', $id);
            }
        }
    }
    return $refs;
}

function parent_of(string $id): string
{
    $p = strpos($id, '.');
    return $p === false ? $id : substr($id, 0, $p);
}

function finding(string $sev, string $rule, string $file, int $line, string $msg): array
{
    return [
        'sev' => $sev, 'rule' => $rule, 'file' => $file, 'line' => $line,
        'where' => $line > 0 ? "$file:$line" : $file, 'msg' => $msg,
    ];
}

/**
 * Audits one file. $cov is updated with the tactics the file covers.
 */
function audit_text(string $text, string $file, array &$cov): array
{
    $yaml = (bool) preg_match('/\.ya?ml$/i', $file);
    $refs = extract_refs($text, $yaml);
    if (count($refs) === 0) {
        return [finding('info', 'MIT000', $file, 0, 'no ATT&CK references found')];
    }
    $out = [];
    $cat = catalogue();
    $dep = deprecated();
    foreach ($refs as $r) {
        switch ($r['kind']) {
            case 'bad':
                $out[] = finding('high', 'MIT001', $file, $r['line'], $r['value'] . ' is not a valid technique ID, use T followed by four digits and an optional dot and three digits');
                break;
            case 'unknown':
                $out[] = finding('low', 'MIT005', $file, $r['line'], 'tag attack.' . $r['value'] . ' is not a tactic, technique, group or software ID');
                break;
            case 'tactic':
                $cov[$r['value']] = true;
                break;
            case 'legacy_tactic':
                $out[] = finding('low', 'MIT006', $file, $r['line'], 'tag attack.defense-evasion predates ATT&CK v18, which split it into stealth and defense-impairment');
                foreach (['stealth', 'defense-impairment'] as $t) {
                    $cov[$t] = true;
                }
                break;
            case 'other_tactic':
                break;
            case 'other':
                $list = $r['value'][0] === 'G' ? ATTACK_GROUPS : ATTACK_SOFTWARE;
                if (!in_array($r['value'], $list, true)) {
                    $out[] = finding('low', 'MIT005', $file, $r['line'], 'tag attack.' . strtolower($r['value']) . ' is not a current ATT&CK group or software ID');
                }
                break;
            case 'id':
                if (!known_technique($r['value'])) {
                    $out[] = finding($yaml ? 'medium' : 'low', 'MIT007', $file, $r['line'], $r['value'] . ' does not exist in ATT&CK ' . ATTACK_VERSION);
                } elseif (array_key_exists($r['value'], $dep)) {
                    $out[] = finding('medium', 'MIT002', $file, $r['line'], $r['value'] . ' is retired in ATT&CK ' . ATTACK_VERSION . ($dep[$r['value']] !== null ? ', use ' . $dep[$r['value']] : ', with no replacement named'));
                } else {
                    foreach ($cat[$r['value']] ?? $cat[parent_of($r['value'])] ?? [] as $t) {
                        $cov[$t] = true;
                    }
                }
                break;
        }
    }
    // parent next to its own sub-technique, per YAML document
    $docs = $yaml ? preg_split('/^---\s*$/m', $text) : [];
    if ($yaml && is_array($docs) && count($docs) > 0) {
        $offset = 0;
        foreach ($docs as $doc) {
            $dr = extract_refs($doc, true);
            $ids = [];
            foreach ($dr as $r) {
                if ($r['kind'] === 'id') {
                    $ids[$r['value']] = $offset + $r['line'];
                }
            }
            foreach ($ids as $id => $line) {
                if (strpos($id, '.') !== false && isset($ids[parent_of($id)])) {
                    $out[] = finding('low', 'MIT003', $file, $ids[parent_of($id)], parent_of($id) . ' is redundant next to ' . $id . ' in the same rule');
                }
            }
            $offset += substr_count($doc, "\n") + 1;
        }
    }
    return $out;
}

function sort_findings(array $f): array
{
    usort($f, function (array $a, array $b): int {
        return [rank($a['sev']), $a['file'], $a['line'], $a['rule'], $a['msg']]
            <=> [rank($b['sev']), $b['file'], $b['line'], $b['rule'], $b['msg']];
    });
    return $f;
}

function list_files(string $path): array
{
    if (!is_dir($path)) {
        return [[basename($path), $path]];
    }
    $files = [];
    $base = rtrim($path, '/');
    $it = new \RecursiveIteratorIterator(
        new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
        \RecursiveIteratorIterator::LEAVES_ONLY,
        \RecursiveIteratorIterator::CATCH_GET_CHILD
    );
    foreach ($it as $f) {
        /** @var \SplFileInfo $f */
        $full = $f->getPathname();
        if ($f->isLink() || !$f->isFile() || strpos($full, '/.git/') !== false) {
            continue;
        }
        if (!in_array(strtolower($f->getExtension()), EXTENSIONS, true)) {
            continue;
        }
        $files[] = [substr($full, strlen($base) + 1), $full];
    }
    usort($files, fn(array $a, array $b): int => strcmp($a[0], $b[0]));
    return $files;
}

/** Returns [findings, fileCount]. */
function audit_path(string $path): array
{
    $files = list_files($path);
    $all = [];
    $cov = [];
    $refsFound = false;
    foreach ($files as [$rel, $full]) {
        $text = '';
        $size = @filesize($full);
        if ($size !== false && $size > 0 && $size <= MAX_BYTES) {
            $t = @file_get_contents($full);
            $text = $t === false ? '' : $t;
        }
        $f = audit_text($text, $rel, $cov);
        foreach ($f as $x) {
            if ($x['rule'] !== 'MIT000') {
                $refsFound = true;
            }
        }
        if (count($f) === 0 || $f[0]['rule'] !== 'MIT000') {
            $refsFound = true;
        }
        array_push($all, ...$f);
    }
    if ($refsFound) {
        foreach (tactics() as $key => $name) {
            if (!isset($cov[$key])) {
                $all[] = finding('low', 'MIT004', '(coverage)', 0, "no detection content in the scanned set references the $name tactic");
            }
        }
    }
    return [sort_findings($all), count($files)];
}
