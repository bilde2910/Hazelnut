<?php
abstract class KeyStorageTestingTemplate extends \PHPUnit\Framework\TestCase {
    private $storage;
    private $identity;
    private $suk;
    private $vuk;

    protected function configure(\Varden\Hazelnut\KeyStorage $storage) :void {
        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $this->identity = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->suk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->vuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->storage = $storage;
    }

    protected function destroy() :void {
        $this->storage = null;
    }

    public function testDefaultState() {
        $result = $this->storage->getState($this->identity);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN, $result);
    }

    public function testCreateIdentity() {
        $this->storage->create($this->identity, $this->suk, $this->vuk);
        $result = $this->storage->getState($this->identity);
        $this->assertNotEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN, $result);
    }

    public function testFetchSUK() {
        $this->storage->create($this->identity, $this->suk, $this->vuk);
        $result = $this->storage->getSUK($this->identity);
        $this->assertEquals($this->suk, $result);
    }

    public function testFetchVUK() {
        $this->storage->create($this->identity, $this->suk, $this->vuk);
        $result = $this->storage->getVUK($this->identity);
        $this->assertEquals($this->vuk, $result);
    }

    public function testDisable() {
        $this->storage->create($this->identity, $this->suk, $this->vuk);
        $this->storage->disable($this->identity);
        $result = $this->storage->getState($this->identity);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED, $result);
    }

    public function testReenable() {
        $this->storage->create($this->identity, $this->suk, $this->vuk);
        $this->storage->disable($this->identity);
        $this->storage->enable($this->identity);
        $result = $this->storage->getState($this->identity);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE, $result);
    }

    public function testMigrate() {
        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $newId = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $newSuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $newVuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));

        $this->storage->create($this->identity, $this->suk, $this->vuk);
        $this->storage->migrate($this->identity, $newId, $newSuk, $newVuk);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN, $this->storage->getState($this->identity));
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE, $this->storage->getState($newId));
        $this->assertEquals($newSuk, $this->storage->getSUK($newId));
        $this->assertEquals($newVuk, $this->storage->getVUK($newId));
    }
}
