<?php
// OpenCSF
/**
 * OpenCSF plugin for cPanel/WHM and CWP
 *
 * Provides a web interface to view CSF settings,
 *
 * Compatible with:
 *   - cPanel/WHM: /usr/local/cpanel/whostmgr/docroot/cgi/imh-open-csf/index.php
 *   - CWP:       /usr/local/cwpsrv/htdocs/resources/admin/modules/imh-open-csf.php
 *
 * Maintainer: InMotion Hosting
 * Version: 0.0.1
 */


// ==========================
// 1. Environment Detection
// 2. Session & Security
// 3. HTML Header & CSS
// 4. Main Interface
// 5-9. Tabs
// 10. HTML Footer
// ==========================





// ==========================
// 1. Environment Detection
// ==========================

declare(strict_types=1);

$isCPanelServer = (
    (is_dir('/usr/local/cpanel') || is_dir('/var/cpanel') || is_dir('/etc/cpanel')) && (is_file('/usr/local/cpanel/cpanel') || is_file('/usr/local/cpanel/version'))
);

$isCWPServer = (
    is_dir('/usr/local/cwp')
);

if ($isCPanelServer) {
    if (getenv('REMOTE_USER') !== 'root') exit('Access Denied');

    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
} else { // CWP
    if (!isset($_SESSION['logged']) || $_SESSION['logged'] != 1 || !isset($_SESSION['username']) || $_SESSION['username'] !== 'root') {
        exit('Access Denied');
    }
};










// ==========================
// 2. Session & Security
// ==========================

$CSRF_TOKEN = NULL;

if (!isset($_SESSION['csrf_token'])) {
    $CSRF_TOKEN = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $CSRF_TOKEN;
} else {
    $CSRF_TOKEN = $_SESSION['csrf_token'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (
        !isset($_POST['csrf_token'], $_SESSION['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
    ) {
        exit("Invalid CSRF token");
    }
}



define('IMH_SAR_CACHE_DIR', '/root/tmp/imh-open-csf');

if (!is_dir(IMH_SAR_CACHE_DIR)) {
    mkdir(IMH_SAR_CACHE_DIR, 0700, true);
}

// Clear old cache files

$cache_dir = IMH_SAR_CACHE_DIR;
$expire_seconds = 3600; // e.g. 1 hour

foreach (glob("$cache_dir/*.cache") as $file) {
    if (is_file($file) && (time() - filemtime($file) > $expire_seconds)) {
        unlink($file);
    }
}

function imh_safe_cache_filename($tag)
{
    return IMH_SAR_CACHE_DIR . '/sar_' . preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', $tag) . '.cache';
}

/**
 * Returns the sar sample interval in seconds (default 600).
 */
function imh_guess_sar_interval()
{
    $cmd = "LANG=C sar -q 2>&1 | grep -E '^[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -2 | awk '{print $1}'";
    $out = safe_shell_exec($cmd, 3);
    if (!is_string($out)) {
        return 600; // fallback if shell_exec failed
    }
    $lines = array_filter(array_map('trim', explode("\n", $out)));
    if (count($lines) < 2) return 600; // fallback
    $t1 = strtotime($lines[0]);
    $t2 = strtotime($lines[1]);
    if ($t1 === false || $t2 === false) return 600;
    $interval = $t2 - $t1;
    if ($interval > 0 && $interval < 3600) return $interval;
    return 600;
}

function imh_cached_shell_exec($tag, $command, $sar_interval)
{
    $cache_file = imh_safe_cache_filename($tag);



    if (file_exists($cache_file)) {
        if (fileowner($cache_file) !== 0) { // 0 = root
            unlink($cache_file);
            // treat as cache miss
        } else {
            $mtime = filemtime($cache_file);
            if (time() - $mtime < $sar_interval) {
                return file_get_contents($cache_file);
            }
        }
    }
    $out = shell_exec($command);
    if (strlen(trim($out))) {
        file_put_contents($cache_file, $out);
    }
    return $out;
}




// Runs a shell command safely with a timeout, preventing hangs.

function safe_shell_exec(string $command, int $timeout = 3): string
{
    static $timeout_bin = null;
    if ($timeout_bin === null) {
        // Find the timeout binary path once
        $found = trim(shell_exec('command -v timeout 2>/dev/null') ?: '');
        $timeout_bin = $found !== '' ? $found : false;
    }

    if ($timeout_bin) {
        // Only escape the path to timeout, not the actual command
        $cmd = escapeshellarg($timeout_bin) . ' ' . (int)$timeout . 's ' . $command;
        $out = shell_exec($cmd);
        return is_string($out) ? $out : '';
    }

    // Fallback: no timeout binary, use proc_open() with stream_select timeout
    $descriptorspec = [
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w']
    ];
    $process = proc_open($command, $descriptorspec, $pipes);
    if (!is_resource($process)) return '';

    $output = '';
    $start = time();
    $readStreams = [$pipes[1], $pipes[2]];

    while (!empty($readStreams) && (time() - $start) < $timeout) {
        $readCopy = $readStreams;
        $write = null;
        $except = null;

        if (stream_select($readCopy, $write, $except, 1) > 0) {
            foreach ($readCopy as $stream) {
                $chunk = stream_get_contents($stream);
                if ($chunk !== false) {
                    $output .= $chunk;
                }
                $key = array_search($stream, $readStreams, true);
                unset($readStreams[$key]);
            }
        }
    }

    foreach ($pipes as $pipe) {
        fclose($pipe);
    }
    proc_terminate($process);
    proc_close($process);

    // Return raw output (don't trim so whitespace/newlines are preserved)
    return is_string($output) ? $output : '';
}




function run_csf_action(string $action): string
{
    global $CSF_ACTIONS;  // use the master actions array

    // derive allowed actions from $CSF_ACTIONS keys
    $allowed_actions = array_keys($CSF_ACTIONS);

    if (!in_array($action, $allowed_actions, true)) {
        return "Action not permitted";
    }

    // Path to csf.pl
    $perl_csf = '/usr/local/cwpsrv/htdocs/resources/admin/modules/csf.pl';

    // Build environment string from ALL POST params (action, ip, comment, etc.)
    $env = http_build_query($_POST);

    // Escape everything safely
    $cmd = escapeshellcmd($perl_csf) . ' ' . escapeshellarg($env);

    // Run with a timeout
    $output = safe_shell_exec($cmd, 10);

    if ($action === 'restart') {
        file_put_contents('/var/lib/csf/last_reload', time());
    }

    return $output ?: "No output from csf.pl";
}












// Defaults and validation

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_time'])) {
    // Reset to defaults
    $start_hour = 0;
    $start_min  = 0;
    $end_hour   = 23;
    $end_min    = 59;
} else {
    $start_hour = min(23, max(0, (int)($_POST['start_hour'] ?? 0)));
    $start_min  = min(59, max(0, (int)($_POST['start_min'] ?? 0)));
    $end_hour   = min(23, max(0, (int)($_POST['end_hour'] ?? 23)));
    $end_min    = min(59, max(0, (int)($_POST['end_min'] ?? 59)));
}


$CSF_ACTIONS = [
    // --- INFO tab / Server Information group ---
    'servercheck' => [
        'label' => 'Check Server Security',
        'desc'  => 'Perform a basic security, stability and settings check on the server.',
        'inputs' => [],
        'tab'   => 'info',
        'group' => 'Server Information'
    ],
    'readme' => [
        'label' => 'Firewall Information',
        'desc'  => 'View the csf+lfd readme.txt file.',
        'inputs' => [],
        'tab'   => 'info',
        'group' => 'Server Information'
    ],
    'logtail' => [
        'label' => 'Watch System Logs',
        'desc'  => 'Tail system logs defined in csf.syslogs.',
        'inputs' => [],
        'tab'   => 'info',
        'group' => 'Server Information'
    ],
    'loggrep' => [
        'label' => 'Search System Logs',
        'desc'  => 'Search system logs (listed in csf.syslogs) with regex or keywords.',
        'inputs' => [],
        'tab'   => 'info',
        'group' => 'Server Information'
    ],
    'viewports' => [
        'label' => 'View Listening Ports',
        'desc'  => 'List listening ports and the executables behind them.',
        'inputs' => [],
        'tab'   => 'info',
        'group' => 'Server Information'
    ],
    'rblcheck' => [
        'label' => 'RBL Check',
        'desc'  => 'Check whether any of the server’s IPs are listed in RBLs.',
        'inputs' => [],
        'tab'   => 'info',
        'group' => 'Server Information'
    ],
    'viewlogs' => [
        'label' => 'View iptables Log',
        'desc'  => 'View recent iptables log entries.',
        'inputs' => [],
        'tab'   => 'info',
        'group' => 'Server Information'
    ],

    // Optional extras if you want stats features
    'chart' => [
        'label' => 'lfd Statistics',
        'desc'  => 'View cumulative blocking statistics for lfd.',
        'inputs' => [],
        'tab'   => 'info',
        'group' => 'Server Information'
    ],
    'systemstats' => [
        'label' => 'System Statistics',
        'desc'  => 'View load, CPU, memory, network, and disk statistics.',
        'inputs' => [],
        'tab'   => 'info',
        'group' => 'Server Information'
    ],

    // Quick Actions
    'qallow' => [
        'label' => 'Quick Allow',
        'desc'  => 'Allow an IP address through the firewall and add to csf.allow (permanent allow list).',
        'inputs' => ['ip', 'comment'],
        'tab'   => 'csf',
        'group' => 'Quick Actions'
    ],
    'qdeny' => [
        'label' => 'Quick Deny',
        'desc'  => 'Block an IP address in the firewall and add to csf.deny (permanent deny list).',
        'inputs' => ['ip', 'comment'],
        'tab'   => 'csf',
        'group' => 'Quick Actions'
    ],
    'qignore' => [
        'label' => 'Quick Ignore',
        'desc'  => 'Ignore an IP address from lfd, add to csf.ignore, and restart lfd.',
        'inputs' => ['ip'],
        'tab'   => 'csf',
        'group' => 'Quick Actions'
    ],
    'kill' => [
        'label' => 'Quick Unblock',
        'desc'  => 'Remove an IP from both temporary and permanent blocks.',
        'inputs' => ['ip'],
        'tab'   => 'csf',
        'group' => 'Quick Actions'
    ],
    // --- Firewall Configuration group ---
    'conf' => [
        'label' => 'Firewall Configuration',
        'desc'  => 'Edit the main configuration file for csf and lfd (csf.conf).',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'profiles' => [
        'label' => 'Firewall Profiles',
        'desc'  => 'Apply pre-configured csf.conf profiles, backup/restore csf.conf.',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'status' => [
        'label' => 'View iptables Rules',
        'desc'  => 'Display the active iptables rules.',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'grep' => [
        'label' => 'Search for IP',
        'desc'  => 'Search iptables and CSF config for an IP address.',
        'inputs' => ['ip'],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'allow' => [
        'label' => 'Firewall Allow IPs',
        'desc'  => 'Edit the permanent allow list (csf.allow).',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'deny' => [
        'label' => 'Firewall Deny IPs',
        'desc'  => 'Edit the permanent deny list (csf.deny).',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'enable' => [
        'label' => 'Firewall Enable',
        'desc'  => 'Enable csf and lfd if previously disabled.',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'disable' => [
        'label' => 'Firewall Disable',
        'desc'  => 'Completely disable csf and lfd.',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'restart' => [
        'label' => 'Firewall Restart',
        'desc'  => 'Restart the csf iptables firewall.',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'restartq' => [
        'label' => 'Firewall Quick Restart',
        'desc'  => 'Restart the csf firewall via lfd (faster).',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'tempdeny' => [
        'label' => 'Temporary Allow/Deny',
        'desc'  => 'Temporarily block or allow an IP for a set duration and optional ports.',
        'inputs' => ['ip', 'do', 'timeout', 'dur', 'ports', 'comment'],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'temp' => [
        'label' => 'Temporary IP Entries',
        'desc'  => 'View or remove currently active temporary allows/denies.',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'sips' => [
        'label' => 'Deny Server IPs',
        'desc'  => 'Deny access to/from specific server IPs (csf.sips).',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'denyf' => [
        'label' => 'Flush all Blocks',
        'desc'  => 'Remove all permanent and temporary blocks (csf.deny, temp bans).',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'redirect' => [
        'label' => 'Firewall Redirect',
        'desc'  => 'Edit csf.redirect to manage connection redirections.',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],
    'fix' => [
        'label' => 'Fix Common Problems',
        'desc'  => 'Apply quick fixes (SPI, SMTP_BLOCK, etc.) for common issues.',
        'inputs' => [],
        'tab'   => 'csf',
        'group' => 'Firewall Configuration'
    ],

    // --- LFD tab / Control group ---
    'lfdstatus' => [
        'label' => 'lfd Status',
        'desc'  => 'Display the current status of the lfd service.',
        'inputs' => [],
        'tab'   => 'lfd',
        'group' => 'Control'
    ],
    'lfdrestart' => [
        'label' => 'lfd Restart',
        'desc'  => 'Restart the lfd service.',
        'inputs' => [],
        'tab'   => 'lfd',
        'group' => 'Control'
    ],
    'lfdstop' => [
        'label' => 'lfd Stop',
        'desc'  => 'Stop the lfd service.',
        'inputs' => [],
        'tab'   => 'lfd',
        'group' => 'Control'
    ],

    // --- LFD tab / Configuration Files group ---
    'ignorefiles' => [
        'label' => 'Edit Ignore Files',
        'desc'  => 'Edit csf.ignore, csf.pignore, csf.fignore, etc.',
        'inputs' => [],
        'tab'   => 'lfd',
        'group' => 'Configuration Files'
    ],
    'dirwatch' => [
        'label' => 'Directory Watch',
        'desc'  => 'Edit csf.dirwatch — files and dirs watched by lfd.',
        'inputs' => [],
        'tab'   => 'lfd',
        'group' => 'Configuration Files'
    ],
    'dyndns' => [
        'label' => 'Dynamic DNS',
        'desc'  => 'Edit csf.dyndns — domains resolved/allowed via firewall.',
        'inputs' => [],
        'tab'   => 'lfd',
        'group' => 'Configuration Files'
    ],
    'templates' => [
        'label' => 'Email Alert Templates',
        'desc'  => 'Edit email alert templates (alert.txt, sshalert.txt, etc.).',
        'inputs' => [],
        'tab'   => 'lfd',
        'group' => 'Configuration Files'
    ],
    'logfiles' => [
        'label' => 'Log Scanner Files',
        'desc'  => 'Edit csf.logfiles — list of log files scanned by lfd.',
        'inputs' => [],
        'tab'   => 'lfd',
        'group' => 'Configuration Files'
    ],
    'blocklists' => [
        'label' => 'Blocklists',
        'desc'  => 'Edit csf.blocklists — configure external blocklists.',
        'inputs' => [],
        'tab'   => 'lfd',
        'group' => 'Configuration Files'
    ],
    'syslogusers' => [
        'label' => 'Syslog Users',
        'desc'  => 'Edit csf.syslogusers — allowed syslog/rsyslog users.',
        'inputs' => [],
        'tab'   => 'lfd',
        'group' => 'Configuration Files'
    ],

    // --- OTHER tab / CloudFlare Firewall ---
    'cloudflare' => [
        'label' => 'CloudFlare',
        'desc'  => 'Access CloudFlare firewall functionality.',
        'inputs' => [],
        'tab'   => 'other',
        'group' => 'CloudFlare Firewall'
    ],
    'cloudflareedit' => [
        'label' => 'CloudFlare Config',
        'desc'  => 'Edit the CloudFlare configuration file (csf.cloudflare).',
        'inputs' => [],
        'tab'   => 'other',
        'group' => 'CloudFlare Firewall'
    ],

    // --- OTHER tab / SMTP AUTH Restrictions ---
    'smtpauth' => [
        'label' => 'SMTP AUTH Restrictions',
        'desc'  => 'Edit csf.smtpauth — allows SMTP AUTH to be advertised to listed IPs.',
        'inputs' => [],
        'tab'   => 'other',
        'group' => 'SMTP AUTH Restrictions'
    ],

    // --- OTHER tab / Reseller Privileges ---
    'reseller' => [
        'label' => 'Reseller Privileges',
        'desc'  => 'Edit csf.resellers — privileges for cPanel, DirectAdmin, or InterWorx resellers.',
        'inputs' => [],
        'tab'   => 'other',
        'group' => 'Reseller Privileges'
    ],

    // --- OTHER tab / Extras ---
    'csftest' => [
        'label' => 'Test iptables',
        'desc'  => 'Run csftest.pl to check that iptables has required modules.',
        'inputs' => [],
        'tab'   => 'other',
        'group' => 'Extras'
    ],
];

function render_csf_inputs(array $inputs)
{
    $html = '';
    foreach ($inputs as $field) {
        switch ($field) {
            case 'ip':
                $html .= '<input type="text" name="ip" placeholder="IP address" required><br>';
                break;
            case 'comment':
                $html .= '<input type="text" name="comment" placeholder="Comment (optional)"><br>';
                break;
            case 'do':
                $html .= '<select name="do"><option value="block">Block</option><option value="allow">Allow</option></select><br>';
                break;
            case 'timeout':
                $html .= '<input type="number" name="timeout" min="1" value="60"> ';
                break;
            case 'dur':
                $html .= '<select name="dur"><option>seconds</option><option selected>minutes</option><option>hours</option><option>days</option></select><br>';
                break;
            case 'ports':
                $html .= '<input type="text" name="ports" value="*" placeholder="*,22,80,443"><br>';
                break;
        }
    }
    return $html;
}

function render_csf_tab(string $tab, array $actions, string $CSRF_TOKEN)
{
    // Group actions by group name
    $grouped = [];
    foreach ($actions as $action => $meta) {
        if ($meta['tab'] === $tab) {
            $grouped[$meta['group']][] = [$action, $meta];
        }
    }

    // Render each group as its own table
    foreach ($grouped as $groupName => $rows) {
        echo '<div class="imh-box">';
        echo '<h3>' . htmlspecialchars($groupName) . '</h3>';
        echo '<div class="imh-table-responsive">';
        echo '<table class="open-csf-tables">';
        echo '<thead><tr><th style="width:25%;">Action</th><th>Description</th></tr></thead><tbody>';

        $alt = false;
        foreach ($rows as [$action, $meta]) {
            $rowClass = $alt ? ' class="imh-table-alt"' : '';
            $alt = !$alt;

            echo "<tr{$rowClass}><td>
                <form method='post'>
                    <input type='hidden' name='csrf_token' value='" . htmlspecialchars($CSRF_TOKEN) . "'>
                    <input type='hidden' name='action' value='{$action}'>"
                . render_csf_inputs($meta['inputs']) .
                "<button type='submit' class='imh-btn imh-red-btn'>{$meta['label']}</button>
                </form>
              </td><td>{$meta['desc']}</td></tr>";
        }

        echo '</tbody></table>';
        echo '</div></div>'; // close imh-box for group
    }
}


// Find local time

$server_time_full = safe_shell_exec('timedatectl', 2);
if (!$server_time_full) {
    $server_time = 'Time unavailable';
} else {
    $server_time_lines = explode("\n", trim($server_time_full));
    $server_time = $server_time_lines[0] ?? 'Time unavailable';
}








// ==========================
// 3. HTML Header & CSS
// ==========================

if ($isCPanelServer) {
    require_once('/usr/local/cpanel/php/WHM.php');
    WHM::header('OpenCSF WHM Interface', 0, 0);
} else {
    echo '<div class="panel-body">';
};








// Styles for the tabs and buttons

?>

<style>
    .panel-body a,
    .imh-box a,
    .imh-footer-box a,
    .imh-box--narrow a,
    .panel-body a,
    .imh-box a,
    .imh-footer-box a,
    .imh-box--narrow a {
        color: #C52227;
    }

    .panel-body a:hover,
    .imh-box a:hover,
    .imh-footer-box a:hover,
    .imh-box--narrow a:hover,
    .panel-body a:focus,
    .imh-box a:focus,
    .imh-footer-box a:focus,
    .imh-box--narrow a:focus {
        color: #d33a41;
    }

    .imh-btn {
        margin: 10px;
        padding: 5px 15px;
        border-radius: 6px;
        font-weight: bold;
    }

    .imh-btn:hover {
        background: #9e181fff;
        color: #ca9e9eff;
    }

    .imh-red-btn {
        background: #C52227;
        color: #fff;
        border: none;
    }

    .imh-piechart-col {
        vertical-align: top;
    }

    .imh-title {
        margin: 0.25em 0 1em 0;
    }

    .imh-title-img {
        margin-right: 0.5em;
    }

    .open-csf-tables {
        border-collapse: collapse;
        margin: 2em 0;
        background: #fafcff;
    }

    .open-csf-tables,
    .open-csf-tables th,
    .open-csf-tables td {
        border: 1px solid #000;
    }

    .open-csf-tables th,
    .open-csf-tables td {
        padding: 4px 8px;
    }

    .open-csf-tables thead {
        background: #e6f2ff;
        color: #333;
        font-weight: 600;
    }

    .open-csf-tables tr.odd-num-table-row {
        background: #f4f4f4;
    }

    .tabs-nav {
        display: flex;
        border-bottom: 1px solid #e3e3e3;
        margin-bottom: 2em;
    }

    .tabs-nav button {
        border: none;
        background: #f8f8f8;
        color: #333;
        padding: 12px 28px;
        cursor: pointer;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        font-size: 1em;
        margin-bottom: -1px;
        border-bottom: 2px solid transparent;
        transition: background 0.15s, border-color 0.15s;
    }

    .tabs-nav button.active {
        background: #fff;
        border-bottom: 2px solid #C52227;
        color: #C52227;
        font-weight: 600;
    }

    .tab-content {
        display: none;
    }

    .tab-content.active {
        display: block;
    }

    .imh-status {
        display: inline-block;
        padding: 6px 18px;
        border-radius: 14px;
        font-weight: 600;
        margin-right: 18px;
        border: 1px solid;
    }

    .imh-status-running {
        background: #e6ffee;
        color: #26a042;
        border-color: #8fd19e;
    }

    .imh-status-notrunning {
        background: #ffeaea;
        color: #c22626;
        border-color: #e99;
    }

    .imh-box {
        margin: 2em 0;
        padding: 1em;
        border: 1px solid #ccc;
        border-radius: 8px;
        display: block;
        background: #f9f9f9;
    }

    .imh-width-full {
        table-layout: fixed;
        width: 100%;
    }

    .imh-box--narrow {
        margin: 1em 0 1em 0;
        padding: 1em;
        border: 1px solid #ccc;
        border-radius: 8px;
        display: block;
        background: #f9f9f9;
    }

    .imh-box--footer {
        margin: 2em 0 2em 0;
        padding: 1em;
        border: 1px solid #ccc;
        border-radius: 8px;
        display: block;
    }

    .imh-pre {
        background: #f8f8f8;
        border: 1px solid #ccc;
        padding: 1em;
        margin: 2em;
    }

    .imh-server-time {
        margin-left: 1em;
        color: #444;
        font-weight: 600;
    }

    .imh-spacer {
        margin-top: 2em;
    }

    .imh-user-section {
        display: block;
        padding: 0.5em 1em;
        border-top: 1px solid black;
    }

    .imh-user-name {
        color: rgb(42, 73, 94);
    }

    .imh-table-alt {
        background: #f4f4f4;
    }

    .imh-alert {
        color: #c00;
        margin: 1em;
    }

    .imh-footer-img {
        margin-bottom: 1em;
    }

    .imh-footer-box {
        margin: 2em 0 2em 0;
        padding: 1em;
        border: 1px solid #ccc;
        border-radius: 8px;
        display: block;
        background: #f9f9f9;
    }

    .imh-small-note {
        font-size: 0.9em;
        color: #555;
    }

    .text-right {
        text-align: right;
    }

    .imh-monospace {
        font-family: monospace;
    }

    .imh-box.margin-bottom {
        margin-bottom: 1em;
    }

    .imh-pid {
        color: #888;
    }

    .panel-body {
        padding-bottom: 5px;
        display: block;
    }

    .imh-collapsible-content {
        max-height: 33333px;
        overflow: hidden;
        transition: max-height 0.3s ease;
    }

    .imh-collapsible-content[aria-hidden="true"] {
        max-height: 0;
    }

    .imh-toggle-btn {
        background: #eee;
        border: 1px solid #999;
        border-radius: 4px;
        cursor: pointer;
        margin-left: 0.5em;
        padding: 2px 10px;
        font-family: monospace;
        font-size: larger;
    }

    .imh-toggle-btn:hover {
        background: #ddd;
        font-weight: bold;
        color: #333;
    }

    .imh-larger-text {
        font-size: 1.5em;
    }

    .imh-table-responsive {
        width: 100%;
        overflow-x: auto;
    }

    @media (max-width: 600px) {

        .open-csf-tables,
        .imh-box,
        .imh-box--narrow,
        .imh-footer-box {
            width: 100% !important;
            min-width: 350px;
            font-size: 0.97em;
        }

        .imh-piechart-col {
            width: 100% !important;
            display: block;
            box-sizing: border-box;
        }

        .open-csf-tables th,
        .open-csf-tables td {
            padding: 4px 4px;
        }

        /* Optionally stack the pie chart columns vertically */
        .open-csf-tables tr {
            display: flex;
            flex-direction: column;
        }
    }

    .chart-container {
        max-height: 800px !important;
        max-width: 800px !important;
        display: block;
        margin-left: auto;
        margin-right: auto;
        background: #fff;
    }

    #PiechartUsersCPU,
    #PiechartUsersMemory {
        width: 100% !important;
        max-width: 100%;
    }
</style>

<?php





// ==========================
// 4. Main Interface
// ==========================

$img_src = $isCWPServer ? 'design/img/imh-open-csf.png' : 'imh-open-csf.png';
echo '<h1 class="imh-title"><img src="' . htmlspecialchars($img_src) . '" alt="open-csf" class="imh-title-img" />OpenCSF</h1>';

$csf_output = '';
$action_output = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'] ?? '';

    if (isset($CSF_ACTIONS[$action])) {
        // If action is in our master array, pass it to csf.pl
        $csf_output = run_csf_action($action);
    } else {
        // Optional: debugging fallback
        $csf_output = "Unknown or unsupported action: " . htmlspecialchars($action);
    }
}

// This is the tab selector.

echo '<div class="tabs-nav" id="imh-tabs-nav">
    <button type="button" class="active" data-tab="tab-info" aria-label="Server Information tab">Server Information</button>
    <button type="button" data-tab="tab-csf" aria-label="csf tab">csf</button>
    <button type="button" data-tab="tab-lfd" aria-label="lfd tab">lfd</button>
    <button type="button" data-tab="tab-other" aria-label="Other tab">Other</button>';





if ($csf_output) {
    $action = $_POST['action'] ?? '';
    $tabLabel = $CSF_ACTIONS[$action]['label'] ?? ucfirst($action);

    echo '<button type="button" class="active" data-tab="tab-csf-output" aria-label="'
        . htmlspecialchars($tabLabel) . ' tab">'
        . htmlspecialchars($tabLabel) . '</button>';
}

echo '</div>';

?>

<script>
    // Tab navigation functionality

    document.querySelectorAll('#imh-tabs-nav button').forEach(function(btn) {
        btn.addEventListener('click', function() {
            // Remove 'active' class from all buttons and tab contents
            document.querySelectorAll('#imh-tabs-nav button').forEach(btn2 => btn2.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            // Activate this button and the corresponding tab
            btn.classList.add('active');
            var tabId = btn.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });

    // Each section can be collapsed or expanded with a button.

    document.addEventListener('DOMContentLoaded', function() {
        // Reset all to inactive first
        if (document.querySelectorAll('#imh-tabs-nav button.active').length > 1) {
            document.querySelectorAll('#imh-tabs-nav button').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));

            // Activate the last tab (our dynamic one)
            let lastTabBtn = document.querySelector('#imh-tabs-nav button:last-child');
            let lastTabId = lastTabBtn.getAttribute('data-tab');

            lastTabBtn.classList.add('active');
            document.getElementById(lastTabId).classList.add('active');
        }
    });
</script>
<?php






// ==========================
// 5. 'Server Information' Tab
// ==========================

echo '<div id="tab-info" class="tab-content active">';

echo '<div class="imh-box">';





// Check current status
$status_cmd = 'systemctl show -p MainPID lfd.service | cut -d= -f2';
$status_output = safe_shell_exec($status_cmd, 3);
$is_running = false;
$pid = null;

if (is_numeric(trim($status_output)) && intval($status_output) > 0) {
    $is_running = true;
    $pid = intval($status_output);
}

function formatElapsedTime($seconds)
{
    $seconds = (int)$seconds;
    $days = floor($seconds / 86400);
    $hours = floor(($seconds % 86400) / 3600);
    $mins = floor(($seconds % 3600) / 60);

    $out = [];
    if ($days > 0) $out[] = "{$days}d";
    if ($hours > 0 || $days > 0) $out[] = "{$hours}h";
    $out[] = "{$mins}m";

    return implode(', ', $out);
}




// csf's status-check box

echo "<div class='imh-box imh-box.margin-bottom'><p class='imh-larger-text'><a target='_blank' href='https://configserver.com/configserver-security-and-firewall/'>csf</a> is a Stateful Packet Inspection (SPI) firewall for Linux servers.</p>";

$csf_active_state_cmd = 'systemctl show -p ActiveState csf.service | cut -d= -f2';
$csf_sub_state_cmd    = 'systemctl show -p SubState csf.service | cut -d= -f2';

$csf_active_state = trim(safe_shell_exec($csf_active_state_cmd, 2));
$csf_sub_state    = trim(safe_shell_exec($csf_sub_state_cmd, 2));

echo '<div class="imh-box">';

if ($csf_active_state === 'active' && $csf_sub_state === 'exited') {

    $reload_file = '/var/lib/csf/last_reload';
    $etime = null;

    if (file_exists($reload_file)) {
        $last_reload = (int) file_get_contents($reload_file);
        if ($last_reload > 0) {
            $etime = time() - $last_reload;
        }
    }

    if ($etime === null) {
        // fallback: systemd timestamp
        $etime = (int) trim(safe_shell_exec(
            'echo $(( $(date +%s) - $(date -d "$(systemctl show -p ActiveEnterTimestamp csf.service | cut -d= -f2-)" +%s) ))',
            2
        ));
    }

    $runtime_str = $etime > 0 ? formatElapsedTime($etime) : '0s';

    echo '<span class="imh-status imh-status-ok">';
    echo 'csf iptables rules last applied ' . htmlspecialchars($runtime_str) . ' ago';
    echo '</span>';
    echo "<span class='imh-pid'>Manual <code>csf -r</code> won't update this.</span>";
} else {
    // Something unusual/wrong
    echo '<span class="imh-status imh-status-notrunning">';
    echo 'Unexpected service state ('
        . htmlspecialchars($csf_active_state . '/' . $csf_sub_state)
        . ')';
    echo '</span>';
}

echo '</div>';
echo "</div>"; // close csf box






// lfd's status-check box

echo "<div class='imh-box imh-box.margin-bottom'><p class='imh-larger-text'>Login Failure Daemon (lfd) periodically scans the latest log file entries for failed login attempts.</p>";



echo '<div class="imh-box">';
if ($is_running) {
    $etime = null;
    if ($pid) {
        $etime = trim(safe_shell_exec('echo $(( $(date +%s) - $(date -d "$(systemctl show -p ActiveEnterTimestamp lfd.service | cut -d= -f2-)" +%s) ))', 2));
    }
    $runtime_str = '';
    if (ctype_digit($etime)) {
        $runtime_str = formatElapsedTime($etime);
    }
    echo '<span class="imh-status imh-status-running">';
    echo 'lfd has been running';
    if ($runtime_str) {
        echo ' for ' . htmlspecialchars($runtime_str);
    }
    echo '</span>';
    echo "<span class='imh-pid'>PID: " . intval($pid) . '</span>';
} else {
    echo '<span class="imh-status imh-status-notrunning">';
    echo 'lfd is not running';
    echo '</span>';

    // Start button.
    echo '
<form method="post">
  <input type="hidden" name="csrf_token" value="' . htmlspecialchars($CSRF_TOKEN) . '">
  <input type="hidden" name="form" value="open_csf_control">
  <input type="hidden" name="action" value="lfdrestart">
  <button type="submit">Start lfd</button>
</form>
    ';
}
echo '</div>';


// System output, if the button was used to start open-csf

if ($action_output) {
    echo "<pre class='imh-pre'>"
        . htmlspecialchars($action_output) . "</pre>";
}

//Close status-check box

echo "</div>";




echo '<div>';
render_csf_tab('info', $CSF_ACTIONS, $CSRF_TOKEN);
echo '</div>';


echo '</div>';
//End of 'All' tab content
echo "</div>";
















// ==========================
// 6. 'csf' Tab
// ==========================

echo '<div id="tab-csf" class="tab-content">';
render_csf_tab('csf', $CSF_ACTIONS, $CSRF_TOKEN);
echo '</div>';









// ==========================
// 7. 'lfd' Tab
// ==========================

echo '<div id="tab-lfd" class="tab-content">';
render_csf_tab('lfd', $CSF_ACTIONS, $CSRF_TOKEN);
echo '</div>';









// ==========================
// 8. 'Other' Tab
// ==========================

echo '<div id="tab-other" class="tab-content">';
render_csf_tab('other', $CSF_ACTIONS, $CSRF_TOKEN);
echo '</div>';







// ==========================
// 8. 'User action' Tab
// ==========================

function scrub_csf_html($html)
{
    // Remove "content-type" header if present
    $html = preg_replace('/^content-type:.*$/mi', '', $html);

    // Remove any generic <h3>...</h3> blocks
    $html = preg_replace('/<h3[^>]*>.*?<\/h3>/is', '', $html);

    // Remove <html>, <head>, <body> wrappers
    $html = preg_replace('/<\/?(html|head|body).*?>/i', '', $html);

    // Remove loader div (and all its contents)
    $html = preg_replace('/<div[^>]*id=["\']loader["\'][^>]*>.*?<\/div>/is', '', $html);

    // Remove font-resize toolbar div
    $html = preg_replace(
        '/<div[^>]*class=["\']pull-right\s+btn-group["\'][^>]*>.*?<\/div>/is',
        '',
        $html
    );

    // Remove everything from start until end of the first <div class="panel panel-default">...</div>
    $html = preg_replace('/^.*?<div\s+class=["\']panel\s+panel-default["\'][^>]*>.*?<\/div>/is', '', $html);

    // Strip out ALL <script>...</script> and <style>...</style> blocks
    $html = preg_replace('/<script\b[^>]*>.*?<\/script>/is', '', $html);
    $html = preg_replace('/<style\b[^>]*>.*?<\/style>/is', '', $html);

    // Find the last closing </table> and truncate after it
    $lastTablePos = strripos($html, '</table>');
    if ($lastTablePos !== false) {
        $html = substr($html, 0, $lastTablePos + strlen('</table>'));
    }

    // Remove footer junk: everything from the <hr><div><form...> marker through the end
    $html = preg_replace('/<hr><div><form.*$/is', '', $html);

    return trim($html);
}



if ($csf_output) {
    $action = $_POST['action'] ?? '';
    // Look up the friendly label in your master actions array
    $tabLabel = $CSF_ACTIONS[$action]['label'] ?? ucfirst($action);

    echo '<div id="tab-csf-output" class="tab-content active">';
    echo '<div class="imh-box">';
    echo '<h3>' . htmlspecialchars($tabLabel) . '</h3>';
    echo scrub_csf_html($csf_output);
    echo '</div>';
    echo '</div>';
}









// ==========================
// 9. HTML Footer
// ==========================

echo '<div class="imh-footer-box"><img src="' . htmlspecialchars($img_src) . '" alt="open-csf" class="imh-footer-img" /><p><a href="https://configserver.com/configserver-security-and-firewall/" target="_blank">ConfigServer Security and Firewall</a> by Way to the Web Ltd.</p><p>Plugin by <a href="https://inmotionhosting.com" target="_blank">InMotion Hosting</a>.</p></div>';




if ($isCPanelServer) {
    WHM::footer();
} else {
    echo '</div>';
};
