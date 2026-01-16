<?php

return [
    'app_key_pass_path' => __DIR__ . '/../storage/config/app_key.pass.json',
    'keystore_dir' => __DIR__ . '/../storage/config/keystore',
    'data_dir' => __DIR__ . '/../storage/data',
    'worker_num' => 1,
    'server' => [
        'host' => '0.0.0.0',
        'port' => 8000,
    ]
];
