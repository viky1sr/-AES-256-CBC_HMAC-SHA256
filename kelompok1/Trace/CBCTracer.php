<?php

namespace Kelompok1\CryptoGraphy\Trace;

/**
 * Class CBCTracer
 * ---------------
 * Tracer per-blok untuk memvisualisasi cara kerja CBC:
 * C1 = AES_ECB( P1 ⊕ IV ), C2 = AES_ECB( P2 ⊕ C1 ), dst.
 *
 * Catatan: hanya untuk edukasi; bukan bagian keamanan inti.
 */
final class CBCTracer
{
    /**
     * Menghasilkan langkah per-blok (P, X=P⊕IV/Cprev, C) dalam hex.
     *
     * @param  string  $plaintext  Akan di-pad agar kelipatan 16 jika perlu.
     * @param  string  $keyEnc  32 byte key untuk AES-ECB (tracing internal saja).
     * @param  string  $iv  IV 16 byte.
     * @return array<int,array{block:int,P:string,X:string,C:string}>
     */
    public static function trace(string $plaintext, string $keyEnc, string $iv): array
    {
        if (strlen($iv) !== 16) {
            throw new \InvalidArgumentException('IV harus 16 byte');
        }
        if (strlen($plaintext) % 16 !== 0) {
            $plaintext = self::pkcs7Pad($plaintext);
        }
        $blocks = str_split($plaintext, 16);
        $prevC = $iv;
        $out = [];
        $i = 0;
        foreach ($blocks as $P) {
            $X = $P ^ $prevC;
            $C = openssl_encrypt($X, 'aes-256-ecb', $keyEnc, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            if ($C === false) {
                throw new \RuntimeException('ECB encrypt gagal');
            }
            $out[] = [
                'block' => ++$i,
                'P' => strtoupper(bin2hex($P)),
                'X' => strtoupper(bin2hex($X)),
                'C' => strtoupper(bin2hex($C)),
            ];
            $prevC = $C;
        }

        return $out;
    }

    private static function pkcs7Pad(string $data, int $blockSize = 16): string
    {
        $pad = $blockSize - (strlen($data) % $blockSize);

        return $data.str_repeat(chr($pad), $pad);
    }
}
