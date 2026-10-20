<?php

namespace App\Services\Security;

use RuntimeException;

class ClamAvScanner
{
    public function scan(string $filePath): array
    {
        if (!is_file($filePath) || !is_readable($filePath)) {
            throw new RuntimeException('Uploaded file is not readable.');
        }

        $host = config('services.clamav.host');
        $port = (int) config('services.clamav.port');
        $timeout = (float) config('services.clamav.timeout', 10);
        $socket = @stream_socket_client(
            "tcp://{$host}:{$port}",
            $errorCode,
            $errorMessage,
            $timeout
        );

        if (!is_resource($socket)) {
            throw new RuntimeException('Could not connect to ClamAV.');
        }

        $file = fopen($filePath, 'rb');
        if (!is_resource($file)) {
            fclose($socket);
            throw new RuntimeException('Could not read uploaded file.');
        }

        try {
            stream_set_timeout($socket, (int) ceil($timeout));
            $this->writeAll($socket, "nINSTREAM\n");

            while (!feof($file)) {
                $chunk = fread($file, 65536);
                if ($chunk === false) {
                    throw new RuntimeException('Could not read uploaded file.');
                }
                if ($chunk !== '') {
                    $this->writeAll($socket, pack('N', strlen($chunk)) . $chunk);
                }
            }

            $this->writeAll($socket, pack('N', 0));
            $response = fgets($socket, 4096);
            $meta = stream_get_meta_data($socket);
            if ($response === false || $meta['timed_out']) {
                throw new RuntimeException('ClamAV did not return a scan result.');
            }

            $response = trim($response);
            if (str_ends_with($response, ' OK')) {
                return ['infected' => false, 'threat' => null];
            }

            if (preg_match('/:\s+(.+)\s+FOUND$/', $response, $matches)) {
                return ['infected' => true, 'threat' => $matches[1]];
            }

            throw new RuntimeException('ClamAV returned an invalid scan result.');
        } finally {
            fclose($file);
            fclose($socket);
        }
    }

    private function writeAll($socket, string $data): void
    {
        $length = strlen($data);
        $offset = 0;

        while ($offset < $length) {
            $written = fwrite($socket, substr($data, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException('Could not send the file to ClamAV.');
            }
            $offset += $written;
        }
    }
}
