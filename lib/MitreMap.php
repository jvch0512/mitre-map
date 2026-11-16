<?php
declare(strict_types=1);

namespace MitreMap;

const RANK = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
const MAX_BYTES = 20000000;
const EXTENSIONS = ['yml', 'yaml', 'yar', 'yara', 'md', 'txt', 'csv', 'tsv', 'json'];

function rank(string $sev): int
{
    return RANK[$sev] ?? 4;
}

/** Enterprise tactics: Sigma tag name => display name. */
function tactics(): array
{
    return [
        'reconnaissance' => 'Reconnaissance',
        'resource_development' => 'Resource Development',
        'initial_access' => 'Initial Access',
        'execution' => 'Execution',
        'persistence' => 'Persistence',
        'privilege_escalation' => 'Privilege Escalation',
        'defense_evasion' => 'Defense Evasion',
        'credential_access' => 'Credential Access',
        'discovery' => 'Discovery',
        'lateral_movement' => 'Lateral Movement',
        'collection' => 'Collection',
        'command_and_control' => 'Command and Control',
        'exfiltration' => 'Exfiltration',
        'impact' => 'Impact',
    ];
}

/** Common parent techniques and the tactics they belong to. Used for coverage only. */
function catalogue(): array
{
    static $c = null;
    if ($c !== null) {
        return $c;
    }
    $by = [
        'reconnaissance' => ['T1595', 'T1592', 'T1589', 'T1590', 'T1593', 'T1598', 'T1591', 'T1594', 'T1596', 'T1597'],
        'resource_development' => ['T1583', 'T1584', 'T1587', 'T1588', 'T1585', 'T1586', 'T1608', 'T1650'],
        'initial_access' => ['T1566', 'T1190', 'T1133', 'T1078', 'T1195', 'T1189', 'T1199', 'T1091', 'T1200'],
        'execution' => ['T1059', 'T1053', 'T1047', 'T1204', 'T1569', 'T1203', 'T1106', 'T1129', 'T1559', 'T1610'],
        'persistence' => ['T1547', 'T1543', 'T1546', 'T1136', 'T1505', 'T1197', 'T1098', 'T1574', 'T1053', 'T1133', 'T1078', 'T1176', 'T1037', 'T1542'],
        'privilege_escalation' => ['T1548', 'T1134', 'T1055', 'T1068', 'T1547', 'T1543', 'T1546', 'T1574', 'T1053', 'T1078', 'T1037', 'T1484'],
        'defense_evasion' => ['T1562', 'T1070', 'T1027', 'T1218', 'T1036', 'T1112', 'T1140', 'T1202', 'T1222', 'T1564', 'T1620', 'T1055', 'T1574', 'T1548', 'T1134', 'T1078', 'T1553', 'T1480', 'T1497', 'T1006', 'T1207', 'T1014'],
        'credential_access' => ['T1003', 'T1110', 'T1555', 'T1558', 'T1056', 'T1552', 'T1557', 'T1539', 'T1528', 'T1111', 'T1212', 'T1187', 'T1606', 'T1556'],
        'discovery' => ['T1082', 'T1083', 'T1087', 'T1018', 'T1016', 'T1049', 'T1057', 'T1069', 'T1135', 'T1046', 'T1033', 'T1007', 'T1012', 'T1518', 'T1124', 'T1217', 'T1482', 'T1526', 'T1580'],
        'lateral_movement' => ['T1021', 'T1570', 'T1550', 'T1210', 'T1534', 'T1563', 'T1072'],
        'collection' => ['T1005', 'T1560', 'T1114', 'T1113', 'T1039', 'T1074', 'T1119', 'T1056', 'T1115', 'T1123', 'T1125', 'T1530', 'T1213'],
        'command_and_control' => ['T1071', 'T1105', 'T1572', 'T1090', 'T1573', 'T1095', 'T1219', 'T1132', 'T1568', 'T1102', 'T1001', 'T1008', 'T1104'],
        'exfiltration' => ['T1041', 'T1048', 'T1567', 'T1020', 'T1030', 'T1029', 'T1537', 'T1052'],
        'impact' => ['T1486', 'T1490', 'T1489', 'T1485', 'T1496', 'T1498', 'T1529', 'T1491', 'T1499', 'T1565', 'T1531'],
    ];
    $c = [];
    foreach ($by as $tactic => $ids) {
        foreach ($ids as $id) {
            $c[$id][] = $tactic;
        }
    }
    return $c;
}

/** Technique IDs retired in the 2020 sub-technique restructuring and what replaced them. */
function deprecated(): array
{
    return [
        'T1086' => 'T1059.001', 'T1064' => 'T1059', 'T1117' => 'T1218.010', 'T1085' => 'T1218.011',
        'T1170' => 'T1218.005', 'T1121' => 'T1218.009', 'T1118' => 'T1218.004', 'T1191' => 'T1218.003',
        'T1089' => 'T1562.001', 'T1060' => 'T1547.001', 'T1050' => 'T1543.003', 'T1073' => 'T1574.002',
        'T1088' => 'T1548.002', 'T1107' => 'T1070.004', 'T1099' => 'T1070.006', 'T1100' => 'T1505.003',
        'T1084' => 'T1546.003', 'T1015' => 'T1546.008', 'T1178' => 'T1134.005', 'T1035' => 'T1569.002',
        'T1028' => 'T1021.006', 'T1076' => 'T1021.001', 'T1077' => 'T1021.002', 'T1193' => 'T1566.001',
        'T1192' => 'T1566.002', 'T1194' => 'T1566.003',
    ];
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
                } elseif (isset(tactics()[$v])) {
                    $add('tactic', $v);
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
            case 'id':
                if (isset($dep[$r['value']])) {
                    $out[] = finding('medium', 'MIT002', $file, $r['line'], $r['value'] . ' is deprecated, use ' . $dep[$r['value']]);
                } else {
                    foreach ($cat[parent_of($r['value'])] ?? [] as $t) {
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
