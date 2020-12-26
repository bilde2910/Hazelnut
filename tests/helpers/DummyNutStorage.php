<?php declare(strict_types=1);
require_once('src/Hazelnut.php');
class DummyNutStorage implements \Varden\Hazelnut\NutStorage {
    private $nuts = array();

    public function retrieve(string $nut) :?\Varden\Hazelnut\Nut {
        if (!isset($this->nuts[$nut])) return null;
        $obj = new \Varden\Hazelnut\Nut($nut);
        return $obj
            -> createdAt($this->nuts[$nut]->created)
            -> forIdentity($this->nuts[$nut]->pubkey)
            -> withTIF($this->nuts[$nut]->tif)
            -> byIP($this->nuts[$nut]->ip);
    }

    public function isVerified(string $origNut) :bool {
        foreach ($this->nuts as $key => $value) {
            if ($value->orig == $origNut) return !!$this->nuts[$key]->verified;
        }
        return false;
    }

    public function deposit(string $nut, string $ip, int $tif, ?string $key) :void {
        if (isset($this->nuts[$nut])) throw new Exception('Nut already exists');
        $this->nuts[$nut] = new DummyNut($ip, $tif, $key, $nut);
    }

    public function replace(string $oldNut, string $newNut, string $ip, int $tif, ?string $key) :void {
        if (!isset($this->nuts[$oldNut])) throw new Exception('Old nut doesn\'t exist');
        if (isset($this->nuts[$newNut])) throw new Exception('New nut already exists');
        $this->nuts[$newNut] = $this->nuts[$oldNut];
        unset($this->nuts[$oldNut]);
        $this->nuts[$newNut]->ip = $ip;
        $this->nuts[$newNut]->tif = $tif;
        $this->nuts[$newNut]->pubkey = $key;
    }

    public function markVerified(string $nut) :void {
        if (!isset($this->nuts[$nut])) throw new Exception('Nut doesn\'t exist');
        $this->nuts[$nut]->verified = 1;
        foreach ($this->nuts as $key => $value) {
            if ($value->orig == $nut) $this->nuts[$key]->verified = 1;
        }
    }

    public function destroy(string $nut) :void {
        if (!isset($this->nuts[$nut])) throw new Exception('Nut doesn\'t exist');
        unset($this->nuts[$nut]);
    }

    public function forceSetNutCreated(string $nut, int $created) :void {
        if (!isset($this->nuts[$nut])) throw new Exception('Nut doesn\'t exist');
        $this->nuts[$nut]->created = $created;
    }

    public function forceSetNutPubkey(string $nut, string $pubkey) :void {
        if (!isset($this->nuts[$nut])) throw new Exception('Nut doesn\'t exist');
        $this->nuts[$nut]->pubkey = $pubkey;
    }

    public function forceSetNutIP(string $nut, string $ip) :void {
        if (!isset($this->nuts[$nut])) throw new Exception('Nut doesn\'t exist');
        $this->nuts[$nut]->ip = $ip;
    }

    public function forceGetOriginal(string $nut) :string {
        if (!isset($this->nuts[$nut])) throw new Exception('Nut doesn\'t exist');
        return $this->nuts[$nut]->orig;
    }
}

class DummyNut {
    public $ip;
    public $tif;
    public $pubkey;
    public $orig;
    public $verified;
    public $created;

    function __construct(string $ip, int $tif, ?string $pubkey, string $orig, bool $verified = false, int $created = -1) {
        $this->ip = $ip;
        $this->tif = $tif;
        $this->pubkey = $pubkey;
        $this->orig = $orig;
        $this->verified = $verified;
        $this->created = $created == -1 ? time() : $created;
    }
}
