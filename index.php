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
 * Version: 0.1.7
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
        margin-left: 15px;
        padding: 5px 15px;
        border-radius: 6px;
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



// This is the tab selector.

echo '<div class="tabs-nav" id="imh-tabs-nav">
    <button type="button" class="active" data-tab="tab-all" aria-label="All tab">All</button>
    <button type="button" data-tab="tab-info" aria-label="Info tab">Info</button>
    <button type="button" data-tab="tab-csf" aria-label="csf tab">csf</button>
    <button type="button" data-tab="tab-lfd" aria-label="lfd tab">lfd</button>
    <button type="button" data-tab="tab-other" aria-label="Other tab">Other</button>
</div>';





// Tab selector script

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
        document.querySelectorAll('.imh-toggle-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var targetId = btn.getAttribute('data-target');
                var collapsed = btn.getAttribute('data-collapsed') === '1';
                var content = document.getElementById(targetId);

                if (collapsed) {
                    // Expand
                    content.setAttribute('aria-hidden', 'false');
                    btn.innerText = '[–]';
                    btn.setAttribute('data-collapsed', '0');
                    btn.setAttribute('aria-expanded', 'true');
                } else {
                    // Collapse
                    content.setAttribute('aria-hidden', 'true');
                    btn.innerText = '[+]';
                    btn.setAttribute('data-collapsed', '1');
                    btn.setAttribute('aria-expanded', 'false');
                }
            });
        });
    });
</script>
<?php






// ==========================
// 5. 'All' Tab
// ==========================

echo '<div id="tab-all" class="tab-content active">';
echo '<h1>All</h1>';





//End of 'All' tab content
echo "</div>";








// ==========================
// 6. 'Info' Tab
// ==========================

echo '<div id="tab-info" class="tab-content active">';
echo '<h1>Info</h1>';






//End of 'Info' tab content
echo "</div>";









// ==========================
// 7. 'csf' Tab
// ==========================

echo '<div id="tab-csf" class="tab-content active">';
echo '<h1>csf</h1>';






//End of 'csf' tab content
echo "</div>";









// ==========================
// 8. 'lfd' Tab
// ==========================

echo '<div id="tab-lfd" class="tab-content active">';
echo '<h1>lfd</h1>';






//End of 'lfd' tab content
echo "</div>";









// ==========================
// 9. 'Other' Tab
// ==========================

echo '<div id="tab-other" class="tab-content active">';
echo '<h1>Other</h1>';






//End of 'Other' tab content
echo "</div>";



















// ==========================
// 10. HTML Footer
// ==========================

echo '<div class="imh-footer-box"><img src="' . htmlspecialchars($img_src) . '" alt="open-csf" class="imh-footer-img" /><p><a href="https://configserver.com/configserver-security-and-firewall/" target="_blank">CSF</a> by Way to the Web Ltd.</p><p>Plugin by <a href="https://inmotionhosting.com" target="_blank">InMotion Hosting</a>.</p></div>';




if ($isCPanelServer) {
    WHM::footer();
} else {
    echo '</div>';
};
