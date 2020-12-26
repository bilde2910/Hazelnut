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

class SqlKeyStorage implements KeyStorage {
    private $pdo;
    private $table;

    function __construct(\PDO $pdo, $table) {
        $this->pdo = $pdo;
        $this->table = $table;
    }

    public function getState(string $identity) :int {
        $state = $this->getIdentityProperty($identity, 'enabled');
        if ($state === false) return self::KEY_STATE_UNKNOWN;
        else if ($state == 1) return self::KEY_STATE_ACTIVE;
        else return self::KEY_STATE_DISABLED;
    }

    public function disable(string $identity) :void {
        $this->setIdentityProperty($identity, 'enabled', 0);
    }

    public function enable(string $identity) :void {
        $this->setIdentityProperty($identity, 'enabled', 1);
    }

    public function getVUK(string $identity) :?string {
        return $this->getIdentityProperty($identity, 'vuk');
    }

    public function getSUK(string $identity) :?string {
        return $this->getIdentityProperty($identity, 'suk');
    }

    public function migrate(string $oldId, string $newId, string $suk, string $vuk) :void {
        $sql = "UPDATE {$this->table} SET pubkey = :new, suk = :suk, vuk = :vuk WHERE pubkey = :old";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':new', $newId, \PDO::PARAM_STR);
        $stmt->bindParam(':suk', $suk, \PDO::PARAM_STR);
        $stmt->bindParam(':vuk', $vuk, \PDO::PARAM_STR);
        $stmt->bindParam(':old', $oldId, \PDO::PARAM_STR);
        $stmt->execute();
    }

    public function create(string $identity, string $suk, string $vuk) :void {
        $sql = "INSERT INTO {$this->table} (pubkey, suk, vuk) VALUES (:pubkey, :suk, :vuk)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':pubkey', $identity, \PDO::PARAM_STR);
        $stmt->bindParam(':suk', $suk, \PDO::PARAM_STR);
        $stmt->bindParam(':vuk', $vuk, \PDO::PARAM_STR);
        $stmt->execute();
    }

    private function getIdentityProperty($identity, $property) {
        $sql = "SELECT {$property} FROM {$this->table} WHERE pubkey = :pubkey";
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindParam(':pubkey', $identity, \PDO::PARAM_STR);
        $stmt->execute();
        return $stmt->fetchColumn();
    }

    private function setIdentityProperty($identity, $property, $value) {
        $sql = "UPDATE {$this->table} SET {$property} = :value WHERE pubkey = :pubkey";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(array(
            ':value' => $value,
            ':pubkey' => $identity
        ));
    }
}
