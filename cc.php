<?php

var_dump(strlen('abcdefghijklmnop'));die;

/**
 * Ubah "HEX dengan/ tanpa spasi" -> string biner (strict).
 */
function hexToBinStrict(string $hex): string
{
    $hex = preg_replace('/\s+/', '', strtoupper($hex));   // buang spasi/newline
    if ($hex === '' || preg_match('/[^0-9A-F]/', $hex)) {
        throw new InvalidArgumentException('Format HEX tidak valid');
    }
    if (strlen($hex) % 2 !== 0) {
        throw new InvalidArgumentException('Panjang HEX harus genap');
    }
    $bin = hex2bin($hex);
    if ($bin === false) {
        throw new RuntimeException('hex2bin gagal');
    }

    return $bin;
}

/** Biner -> HEX kelompok (biar rapi di print) */
function binToHexGrouped(string $bin): string
{
    $hex = strtoupper(bin2hex($bin));
    $parts = str_split($hex, 4); // 2 byte per grup
    $out = [];
    foreach ($parts as $i => $p) {
        $out[] = $p;
        if (($i + 1) % 4 === 0 && ($i + 1) < count($parts)) {
            $out[] = ' ';
        }
    }

    return implode(' ', $out);
}

// contoh pakai:
$rkHex = '04C0DD9A C66248DA 40C20464 08476B49';
$rkBin = hexToBinStrict($rkHex);               // → 16 byte
echo strlen($rkBin), PHP_EOL;                  // 16
echo binToHexGrouped($rkBin), PHP_EOL;         // kembali ke format rapi
