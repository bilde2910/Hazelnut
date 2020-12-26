<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::handleQuery
 * @uses \Varden\Hazelnut\Authenticator
 * @uses DummyKey
 * @uses DummyKeyStorage
 * @uses DummyNut
 * @uses DummyNutStorage
 */
class CoreHandleQueryTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $keyStore;
    private $nutStore;
    private $method;

    private $dataIdk;
    private $dataSuk;
    private $dataVuk;
    private $dataPidk;

    protected function setUp() :void {
        $this->keyStore = new DummyKeyStorage();
        $this->nutStore = new DummyNutStorage();
        $this->hazelnut = new \Varden\Hazelnut\Authenticator($this->keyStore, $this->nutStore);;
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'handleQuery');
        $this->method->setAccessible(true);

        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $this->dataIdk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->dataSuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->dataVuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->dataPidk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
    }

    public function testQueryActiveIdkWithoutPidk() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $client = array('idk' => $this->dataIdk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(\Varden\Hazelnut\TIF_CID_MATCH, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE, $this->keyStore->getState($this->dataIdk));
    }

    public function testQueryActiveIdkWithActivePidk() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->create($this->dataPidk, $this->dataSuk, $this->dataVuk);

        $client = array('idk' => $this->dataIdk, 'pidk' => $this->dataPidk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(\Varden\Hazelnut\TIF_CID_MATCH, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE, $this->keyStore->getState($this->dataIdk));
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE, $this->keyStore->getState($this->dataPidk));
    }

    public function testQueryActiveIdkWithDisabledPidk() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->create($this->dataPidk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->disable($this->dataPidk);

        $client = array('idk' => $this->dataIdk, 'pidk' => $this->dataPidk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(\Varden\Hazelnut\TIF_CID_MATCH, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE, $this->keyStore->getState($this->dataIdk));
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED, $this->keyStore->getState($this->dataPidk));
    }

    public function testQueryActiveIdkWithUnknownPidk() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);

        $client = array('idk' => $this->dataIdk, 'pidk' => $this->dataPidk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(\Varden\Hazelnut\TIF_CID_MATCH, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE, $this->keyStore->getState($this->dataIdk));
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN, $this->keyStore->getState($this->dataPidk));
    }

    public function testQueryDisabledIdkWithoutPidk() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->disable($this->dataIdk);

        $client = array('idk' => $this->dataIdk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(\Varden\Hazelnut\TIF_CID_MATCH | \Varden\Hazelnut\TIF_ID_DISABLED, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED, $this->keyStore->getState($this->dataIdk));
    }

    public function testQueryDisabledIdkWithActivePidk() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->create($this->dataPidk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->disable($this->dataIdk);

        $client = array('idk' => $this->dataIdk, 'pidk' => $this->dataPidk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(\Varden\Hazelnut\TIF_CID_MATCH | \Varden\Hazelnut\TIF_ID_DISABLED, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED, $this->keyStore->getState($this->dataIdk));
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE, $this->keyStore->getState($this->dataPidk));
    }

    public function testQueryDisabledIdkWithDisabledPidk() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->create($this->dataPidk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->disable($this->dataIdk);
        $this->keyStore->disable($this->dataPidk);

        $client = array('idk' => $this->dataIdk, 'pidk' => $this->dataPidk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(\Varden\Hazelnut\TIF_CID_MATCH | \Varden\Hazelnut\TIF_ID_DISABLED, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED, $this->keyStore->getState($this->dataIdk));
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED, $this->keyStore->getState($this->dataPidk));
    }

    public function testQueryDisabledIdkWithUnknownPidk() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->disable($this->dataIdk);

        $client = array('idk' => $this->dataIdk, 'pidk' => $this->dataPidk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(\Varden\Hazelnut\TIF_CID_MATCH | \Varden\Hazelnut\TIF_ID_DISABLED, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED, $this->keyStore->getState($this->dataIdk));
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN, $this->keyStore->getState($this->dataPidk));
    }

    public function testQueryUnknownIdkWithoutPidk() {
        $client = array('idk' => $this->dataIdk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(0, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN, $this->keyStore->getState($this->dataIdk));
    }

    public function testQueryUnknownIdkWithActivePidk() {
        $this->keyStore->create($this->dataPidk, $this->dataSuk, $this->dataVuk);
        $client = array('idk' => $this->dataIdk, 'pidk' => $this->dataPidk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(\Varden\Hazelnut\TIF_PID_MATCH, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN, $this->keyStore->getState($this->dataIdk));
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE, $this->keyStore->getState($this->dataPidk));
    }

    public function testQueryUnknownIdkWithDisabledPidk() {
        $this->keyStore->create($this->dataPidk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->disable($this->dataPidk);
        $client = array('idk' => $this->dataIdk, 'pidk' => $this->dataPidk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(0, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN, $this->keyStore->getState($this->dataIdk));
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED, $this->keyStore->getState($this->dataPidk));
    }

    public function testQueryUnknownIdkWithUnknownPidk() {
        $client = array('idk' => $this->dataIdk, 'pidk' => $this->dataPidk);
        $result = $this->method->invoke($this->hazelnut, $client);
        $this->assertEquals(0, $result);
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN, $this->keyStore->getState($this->dataIdk));
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN, $this->keyStore->getState($this->dataPidk));
    }
}
