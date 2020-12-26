<?php declare(strict_types=1);

/*
Copyright 2020 Marius Lindvall

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

namespace Varden\Hazelnut;

class SqlNutStorage implements NutStorage {
    private $pdo;
    private $table;

    function __construct(\PDO $pdo, $table) {
        $this->pdo = $pdo;
        $this->table = $table;
    }

    public function retrieve(string $nut) :?Nut {
        $sql = "SELECT pubkey, created, tif, network, host FROM {$this->table} WHERE nut = :nut";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':nut', $nut, \PDO::PARAM_STR);
        $stmt->execute();
        $result = $stmt->fetch(\PDO::FETCH_ASSOC);
        if (empty($result)) return null;

        $net = str_pad(dechex($result['network']), 16, '0', STR_PAD_LEFT);
        $host = str_pad(dechex($result['host']), 16, '0', STR_PAD_LEFT);
        $ipv6addr = trim(chunk_split($net.$host, 4, ':'), ':');
        $obj = new Nut($nut);
        return $obj
            -> createdAt(strtotime($result['created']))
            -> forIdentity($result['pubkey'])
            -> withTIF(intval($result['tif']))
            -> byIP($ipv6addr);
    }

    public function isVerified(string $origNut) :bool {
        $sql = "SELECT verified FROM {$this->table} WHERE orig = :nut LIMIT 1";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':nut', $origNut, \PDO::PARAM_STR);
        $stmt->execute();
        $result = $stmt->fetchColumn();
        return !!$result;
    }

    public function deposit(string $nut, string $ip, int $tif, ?string $key) :void {
        $iphex = str_replace(':', '', $ip);
        $sql = "INSERT INTO {$this->table} (nut, orig, network, host, pubkey, tif) VALUES (:nut, :nut, :network, :host, :pubkey, :tif)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':nut', $nut, \PDO::PARAM_STR);
        $stmt->bindValue(':network', hexdec(substr($iphex, 0, 16)), \PDO::PARAM_INT);
        $stmt->bindValue(':host', hexdec(substr($iphex, 16)), \PDO::PARAM_INT);
        $stmt->bindParam(':tif', $tif, \PDO::PARAM_INT);
        $stmt->bindParam(':pubkey', $key, \PDO::PARAM_STR);
        $stmt->execute();
    }

    public function replace(string $oldNut, string $newNut, string $ip, int $tif, ?string $key) :void {
        $iphex = str_replace(':', '', $ip);
        $sql = "UPDATE {$this->table} SET nut = :new, network = :network, host = :host, pubkey = :pubkey, tif = :tif WHERE nut = :old";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':new', $newNut, \PDO::PARAM_STR);
        $stmt->bindValue(':network', hexdec(substr($iphex, 0, 16)), \PDO::PARAM_INT);
        $stmt->bindValue(':host', hexdec(substr($iphex, 16)), \PDO::PARAM_INT);
        $stmt->bindParam(':tif', $tif, \PDO::PARAM_INT);
        $stmt->bindParam(':pubkey', $key, \PDO::PARAM_STR);
        $stmt->bindParam(':old', $oldNut, \PDO::PARAM_STR);
        $stmt->execute();
    }

    public function markVerified(string $nut) :void {
        $sql = "UPDATE {$this->table} SET verified = 1 WHERE nut = :nut OR orig = :nut";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':nut', $nut, \PDO::PARAM_STR);
        $stmt->execute();
    }

    public function destroy(string $nut) :void {
        $sql = "DELETE FROM {$this->table} WHERE nut = :nut OR orig = :nut";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':nut', $nut, \PDO::PARAM_STR);
        $stmt->execute();
    }
}
