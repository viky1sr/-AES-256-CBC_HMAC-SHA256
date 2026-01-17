<?php
require_once __DIR__ . '/vendor/autoload.php';

$id = '0f621f0e36891917f7c2de20662f5e3b';
$datFile = __DIR__ . '/storage/data/chats/000/' . $id . '.dat';

if (file_exists($datFile)) {
    $content = file_get_contents($datFile);
    echo "ID: $id\n";
    echo "Size: " . strlen($content) . " bytes\n";
    echo "Hex: " . bin2hex($content) . "\n";
} else {
    echo "File not found: $datFile\n";
}
