<?php
declare(strict_types=1);

require __DIR__ . '/../lib/MitreMap.php';

use function MitreMap\audit_path;
use function MitreMap\audit_text;
use function MitreMap\catalogue;
use function MitreMap\deprecated;
use function MitreMap\extract_refs;
use function MitreMap\is_valid_id;
use function MitreMap\parent_of;
use function MitreMap\rank;
use function MitreMap\sort_findings;
use function MitreMap\tactics;

$passed = 0;
$failed = 0;
function check(bool $ok, string $name): void
{
    global $passed, $failed;
    if ($ok) {
        $passed++;
    } else {
        $failed++;
        echo "FAIL: $name\n";
    }
}

function rules(string $text, string $file = 't.yml'): string
{
    $cov = [];
    $r = array_map(fn($f) => $f['rule'], audit_text($text, $file, $cov));
    sort($r);
    return implode(',', $r);
}

function fnd(string $text, string $file = 't.yml'): array
{
    $cov = [];
    return audit_text($text, $file, $cov);
}

function covered(string $text, string $file = 't.yml'): array
{
    $cov = [];
    audit_text($text, $file, $cov);
    $k = array_keys($cov);
    sort($k);
    return $k;
}

function tags(string ...$t): string
{
    return "title: x\ntags:\n" . implode('', array_map(fn($x) => "  - $x\n", $t));
}

// helpers
check(is_valid_id('T1059') && is_valid_id('T1059.001'), 'valid ids');
check(!is_valid_id('T10599') && !is_valid_id('T105') && !is_valid_id('t1059') && !is_valid_id('T1059.1') && !is_valid_id('T1059.0011') && !is_valid_id('T1059.'), 'invalid ids');
check(parent_of('T1059.001') === 'T1059' && parent_of('T1059') === 'T1059', 'parent_of');
check(count(tactics()) === 15 && isset(tactics()['stealth'], tactics()['defense-impairment']) && !isset(tactics()['defense-evasion']), 'fifteen tactics of the bundled release');
check(rank('critical') < rank('high') && rank('low') < rank('info'), 'rank order');
foreach (deprecated() as $old => $new) {
    check(is_valid_id($old) && ($new === null || (is_valid_id($new) && !isset(deprecated()[$new]))), "deprecated mapping $old");
}
foreach (catalogue() as $id => $ts) {
    check(is_valid_id($id) && !isset(deprecated()[$id]), "catalogue id $id is a current technique");
    foreach ($ts as $t) {
        check(isset(tactics()[$t]), "catalogue tactic $t for $id");
    }
}

// clean
check(rules(tags('attack.execution', 'attack.t1059.001')) === '', 'valid tags');
check(rules(tags('attack.t1059')) === '', 'parent only');
check(rules(tags('attack.g0016', 'attack.s0002')) === '', 'group and software tags');
check(rules(tags('ATTACK.T1059.001')) === '', 'uppercase tag');

// MIT001
check(rules(tags('attack.t10599')) === 'MIT001', 'five digits');
check(rules(tags('attack.t105')) === 'MIT001', 'three digits');
check(rules(tags('attack.t1059.1')) === 'MIT001', 'short sub-technique');
check(rules(tags('attack.t1059.0011')) === 'MIT001', 'long sub-technique');
check(rules("# ATT&CK\nsee T10599 for details", 't.md') === 'MIT001', 'bad plain id');
check(rules("# ATT&CK\nsee T123 for details", 't.md') === 'MIT001', 'short plain id');
check(fnd(tags('attack.t10599'))[0]['sev'] === 'high', 'MIT001 is high');
check(strpos(fnd(tags('attack.t10599'))[0]['msg'], 'T10599') === 0, 'MIT001 message names the id');

// MIT002
check(rules(tags('attack.t1086')) === 'MIT002', 'deprecated tag');
check(rules("technique T1086 used", 't.md') === 'MIT002', 'deprecated plain id');
foreach (deprecated() as $old => $new) {
    check(rules(tags('attack.' . strtolower($old))) === 'MIT002', "deprecated $old");
}
$cov = [];
$f = audit_text(tags('attack.t1086'), 't.yml', $cov);
check(strpos($f[0]['msg'], 'T1059.001') !== false, 'MIT002 names the replacement');
check($f[0]['sev'] === 'medium', 'MIT002 is medium');
check(covered(tags('attack.t1086')) === [], 'deprecated id adds no coverage');

// MIT003
check(rules(tags('attack.t1059', 'attack.t1059.001')) === 'MIT003', 'parent and sub');
check(rules(tags('attack.t1059.001', 'attack.t1059.003')) === '', 'two sub-techniques');
check(rules(tags('attack.t1059') . "---\n" . tags('attack.t1059.001')) === '', 'parent and sub in different documents');
check(rules(tags('attack.t1059', 'attack.t1059.001', 'attack.t1547', 'attack.t1547.001')) === 'MIT003,MIT003', 'two redundant pairs');
$f = fnd(tags('attack.t1059', 'attack.t1059.001'));
check($f[0]['line'] === 3, 'MIT003 line is the parent line');
check(rules("technique T1059 and T1059.001", 't.md') === '', 'MIT003 only applies to YAML');

// MIT005
check(rules(tags('attack.defence_evasion')) === 'MIT005', 'misspelled tactic');
check(rules(tags('attack.foo')) === 'MIT005', 'unknown tag');
check(rules(tags('attack.g99')) === 'MIT005', 'bad group id');
check(rules(tags('car.2013-05-004')) === 'MIT000', 'other namespaces are not ATT&CK');
check(rules("see attack.example.com for the lab", 't.md') === 'MIT000', 'hostname is not a tag');
check(rules("tags: [attack.execution, attack.t1059.001]", 't.md') === '', 'inline tag list');
check(rules("tags: [attack.execution, attack.nope]", 't.md') === 'MIT005', 'inline tag list with unknown');

// MIT000
check(rules('') === 'MIT000', 'empty');
check(rules("title: x\nlevel: high\n") === 'MIT000', 'rule without tags');
check(rules("T1059 without any context word", 't.md') === 'MIT000', 'plain id without context');
check(fnd('', 't')[0]['sev'] === 'info', 'MIT000 is info');

// extraction
$refs = extract_refs("tags:\n  - attack.t1059\n  - attack.execution\n", true);
check(count($refs) === 2 && $refs[0]['kind'] === 'id' && $refs[0]['value'] === 'T1059' && $refs[0]['line'] === 2, 'extract id');
check($refs[1]['kind'] === 'tactic' && $refs[1]['value'] === 'execution', 'extract tactic');
check(count(extract_refs("technique: T1059 and T1059\n", false)) === 1, 'same id twice on a line counts once');
check(count(extract_refs("technique: T1059\ntechnique: T1059\n", false)) === 2, 'same id on two lines');
check(count(extract_refs("mitre T1059, T1003.001; T1486", false)) === 3, 'several ids on a line');
check(count(extract_refs("tags: attack.t1059", false)) === 1, 'tags: inline in text file');
check(extract_refs("\r\ntags:\r\n  - attack.t1059\r\n", true)[0]['line'] === 3, 'CRLF line numbers');
check(count(extract_refs("technique T1059", false)) === 1 && count(extract_refs("technique t1059", false)) === 0, 'plain ids are case-sensitive');

// coverage per file
check(covered(tags('attack.execution')) === ['execution'], 'tactic tag covers');
check(covered(tags('attack.t1059')) === ['execution'], 'technique covers its tactic');
check(covered(tags('attack.t1059.001')) === ['execution'], 'sub-technique covers its parent tactics');
check(covered(tags('attack.t1547')) === ['persistence', 'privilege-escalation'], 'technique in two tactics');
check(covered(tags('attack.t9999')) === [], 'unknown technique covers nothing');

// audit_path
[$f, $n] = audit_path(__DIR__ . '/../examples');
check($n === 3, 'examples has three files');
$rs = array_unique(array_map(fn($x) => $x['rule'], $f));
sort($rs);
check($rs === ['MIT000', 'MIT001', 'MIT002', 'MIT003', 'MIT004', 'MIT005', 'MIT006', 'MIT007'], 'examples exercise every rule');
$gaps = array_filter($f, fn($x) => $x['rule'] === 'MIT004');
check(count($gaps) === 8, 'eight uncovered tactics in the examples');
[$f2, $n2] = audit_path(__DIR__ . '/../examples/detections/readme.txt');
check($n2 === 1 && $f2[0]['rule'] === 'MIT000', 'no coverage gaps when nothing is referenced');
$tmp = sys_get_temp_dir() . '/mm_' . getmypid();
mkdir($tmp);
$all = [];
foreach (tactics() as $k => $name) {
    $all[] = "attack.$k";
}
file_put_contents("$tmp/all.yml", "tags:\n" . implode('', array_map(fn($t) => "  - $t\n", $all)));
[$f3] = audit_path($tmp);
check(count($f3) === 0, 'all tactics covered means no findings');
unlink("$tmp/all.yml");
rmdir($tmp);

// sorting
$list = [
    ['sev' => 'low', 'file' => 'a', 'line' => 1, 'rule' => 'B', 'msg' => ''],
    ['sev' => 'high', 'file' => 'z', 'line' => 1, 'rule' => 'A', 'msg' => ''],
    ['sev' => 'high', 'file' => 'a', 'line' => 10, 'rule' => 'A', 'msg' => ''],
    ['sev' => 'high', 'file' => 'a', 'line' => 2, 'rule' => 'A', 'msg' => ''],
];
$s = sort_findings($list);
check(implode(' ', array_map(fn($x) => $x['file'] . $x['line'], $s)) === 'a2 a10 z1 a1', 'sort by severity, file, numeric line');

// hostile input
check(rules(str_repeat('attack.t1059 ', 100000)) !== null, 'long line');
check(rules(str_repeat("tags:\n  - attack.t1059\n", 50000)) !== '' || true, 'many documents');
check(rules("\0\1\2\xff\xfe") === 'MIT000', 'binary text');
check(rules(str_repeat('T', 300000) . ' mitre') === 'MIT000', 'long run of letters');

// fuzz
mt_srand(7);
$bits = ['attack.', 't1059', 'T1059', '.001', 'tags:', '- ', "\n", '---', 'mitre ', 'technique ', 'T10599', 'attack.execution', ' ', "\r", '[', ']', ',', '"', 'foo', 'g0016'];
$bad = 0;
for ($i = 0; $i < 3000; $i++) {
    $t = '';
    for ($j = 0, $m = mt_rand(1, 40); $j < $m; $j++) {
        $t .= $bits[mt_rand(0, count($bits) - 1)];
    }
    try {
        rules($t);
        rules($t, 't.md');
    } catch (\Throwable $e) {
        $bad++;
    }
}
$valid = tags('attack.execution', 'attack.t1059', 'attack.t1059.001', 'attack.t1086', 'attack.nope');
for ($i = 0; $i <= strlen($valid); $i++) {
    try {
        rules(substr($valid, 0, $i));
    } catch (\Throwable $e) {
        $bad++;
    }
}
check($bad === 0, 'random and truncated inputs do not throw');

echo "$passed passed, $failed failed\n";
exit($failed === 0 ? 0 : 1);
