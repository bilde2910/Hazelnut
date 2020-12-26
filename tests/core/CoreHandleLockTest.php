<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::handleLock
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 * @uses DummyKey
 * @uses DummyKeyStorage
 * @uses DummyNut
 * @uses DummyNutStorage
 */
class CoreHandleLockTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $keyStore;
    private $nutStore;
    private $method;

    private $dataIdk;
    private $dataSuk;
    private $dataVuk;
    private $dataNut;

    protected function setUp() :void {
        $this->keyStore = new DummyKeyStorage();
        $this->nutStore = new DummyNutStorage();
        $this->hazelnut = new \Varden\Hazelnut\Authenticator($this->keyStore, $this->nutStore);
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'handleLock');
        $this->method->setAccessible(true);

        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $this->dataIdk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->dataSuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->dataVuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->dataNut = $this->hazelnut->createAuthSession();
    }

    public function testLockUnknownKey() {
        $client = array('idk' => $this->dataIdk);

        $result = $this->method->invoke($this->hazelnut, $client, $this->dataNut);
        $this->assertNotNull($this->nutStore->retrieve($this->dataNut));
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result
        );
    }

    public function testLockKnownKey() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $client = array('idk' => $this->dataIdk);

        $result = $this->method->invoke($this->hazelnut, $client, $this->dataNut);
        $this->assertNull($this->nutStore->retrieve($this->dataNut));
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED,
            $this->keyStore->getState($this->dataIdk)
        );
        $this->assertEquals(
            \Varden\Hazelnut\TIF_CID_MATCH |
            \Varden\Hazelnut\TIF_ID_DISABLED,
            $result
        );
    }
}
