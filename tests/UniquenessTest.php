<?php
require_once 'vendor/autoload.php';
use Kelompok1\CryptoGraphy\Services\FileSecureStorage;
use Kelompok1\CryptoGraphy\Token\EtmToken;

$tempDir = 'storage/test/unique_test';
if (!is_dir($tempDir)) mkdir($tempDir, 0777, true);
$storage = new FileSecureStorage($tempDir);

$iterations = 1000;
$processCount = 10;
$perProcess = $iterations / $processCount;
$startTime = microtime(true);

echo "Starting Multi-Process Uniqueness Test ($processCount processes, total $iterations items)...\n";

$pids = [];
for ($p = 0; $p < $processCount; $p++) {
    $pid = pcntl_fork();
    if ($pid == -1) {
        die("Could not fork process $p\n");
    } elseif ($pid) {
        // Parent
        $pids[] = $pid;
    } else {
        // Child
        $childIds = [];
        $childStart = microtime(true);
        for ($i = 0; $i < $perProcess; $i++) {
            $plaintext = "Proc-$p-Item-$i-" . bin2hex(random_bytes(8));
            $token = EtmToken::pack(random_bytes(16), $plaintext, random_bytes(32));
            $id = $storage->save($token);
            
            if (isset($childIds[$id])) {
                echo "COLLISION DETECTED in child $p! ID: $id\n";
                exit(1);
            }
            $childIds[$id] = true;
        }
        $childEnd = microtime(true);
        // echo "Child $p finished " . count($childIds) . " items in " . round($childEnd - $childStart, 2) . "s\n";
        exit(0);
    }
}

// Wait for all children
foreach ($pids as $pid) {
    pcntl_waitpid($pid, $status);
    if (pcntl_wexitstatus($status) !== 0) {
        die("A child process failed or detected a collision.\n");
    }
}

$endTime = microtime(true);
$duration = $endTime - $startTime;

echo "SUCCESS: No collisions found in $iterations iterations across $processCount processes.\n";
echo "Total Time: " . round($duration, 2) . " seconds\n";
