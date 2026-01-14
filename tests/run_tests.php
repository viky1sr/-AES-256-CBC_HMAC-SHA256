<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/AntiTamperTest.php';
require_once __DIR__ . '/CryptoServiceTest.php';
require_once __DIR__ . '/RegisterStorageTest.php';
require_once __DIR__ . '/ChatVisibilityTest.php';

use Kelompok1\CryptoGraphy\Tests\AntiTamperTest;
use Kelompok1\CryptoGraphy\Tests\CryptoServiceTest;
use Kelompok1\CryptoGraphy\Tests\RegisterStorageTest;
use Kelompok1\CryptoGraphy\Tests\ChatVisibilityTest;

$logFile = __DIR__ . '/test_results.log';
$timestamp = date('Y-m-d H:i:s');
$output = "========================================\n";
$output .= "TEST RUN: $timestamp\n";
$output .= "========================================\n\n";

echo "Running tests...\n";

$testers = [
    new AntiTamperTest(),
    new CryptoServiceTest(),
    new RegisterStorageTest(),
    new ChatVisibilityTest()
];

foreach ($testers as $tester) {
    $results = $tester->run();
    foreach ($results as $res) {
        $line = sprintf("[%s] %s: %s\n", $res['status'], $res['name'], $res['message']);
        echo $line;
        $output .= $line;
    }
}

$output .= "\n" . str_repeat("-", 40) . "\n\n";

file_put_contents($logFile, $output, FILE_APPEND);
echo "\nResults saved to $logFile\n";
