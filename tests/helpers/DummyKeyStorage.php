<?php declare(strict_types=1);
require_once('src/Hazelnut.php');
class DummyKeyStorage implements \Varden\Hazelnut\KeyStorage {
    private $keys = array();

    public function getState(string $identity) :int {
        if (!isset($this->keys[$identity])) return self::KEY_STATE_UNKNOWN;
        else if ($this->keys[$identity]->enabled) return self::KEY_STATE_ACTIVE;
        else return self::KEY_STATE_DISABLED;
    }

    public function disable(string $identity) :void {
        if (!isset($this->keys[$identity])) throw new Exception('Identity doesn\'t exist');
        $this->keys[$identity]->enabled = false;
    }

    public function enable(string $identity) :void {
        if (!isset($this->keys[$identity])) throw new Exception('Identity doesn\'t exist');
        $this->keys[$identity]->enabled = true;
    }

    public function getVUK(string $identity) :?string {
        if (!isset($this->keys[$identity])) return null;
        return $this->keys[$identity]->vuk;
    }

    public function getSUK(string $identity) :?string {
        if (!isset($this->keys[$identity])) return null;
        return $this->keys[$identity]->suk;
    }

    public function migrate(string $oldId, string $newId, string $suk, string $vuk) :void {
        if (!isset($this->keys[$oldId])) throw new Exception('Old identity doesn\'t exist');
        if (isset($this->keys[$newId])) throw new Exception('New identity already exists');
        $this->keys[$newId] = $this->keys[$oldId];
        unset($this->keys[$oldId]);
        $this->keys[$newId]->suk = $suk;
        $this->keys[$newId]->vuk = $vuk;
    }

    public function create(string $identity, string $suk, string $vuk) :void {
        if (isset($this->keys[$identity])) throw new Exception('Identity already exists');
        $this->keys[$identity] = new DummyKey($suk, $vuk);
    }
}

class DummyKey {
    public $suk;
    public $vuk;
    public $enabled;

    function __construct(string $suk, string $vuk, bool $enabled = true) {
        $this->suk = $suk;
        $this->vuk = $vuk;
        $this->enabled = $enabled;
    }
}
