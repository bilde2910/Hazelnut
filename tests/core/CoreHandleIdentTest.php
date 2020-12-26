<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::handleIdent
 * @uses \Varden\Hazelnut\Authenticator
 * @uses DummyKey
 * @uses DummyKeyStorage
 * @uses DummyNut
 * @uses DummyNutStorage
 */
class CoreHandleIdentTest extends \PHPUnit\Framework\TestCase {
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
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'handleIdent');
        $this->method->setAccessible(true);

        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $this->dataIdk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->dataSuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->dataVuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->dataNut = $this->hazelnut->createAuthSession();
    }

    public function testIdentActiveKey() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $client = array('idk' => $this->dataIdk);

        $result = $this->method->invoke($this->hazelnut, $client, $this->dataNut);
        $this->assertTrue($this->nutStore->isVerified($this->dataNut));
        $this->assertEquals(
            \Varden\Hazelnut\TIF_CID_MATCH,
            $result
        );
    }

    public function testIdentDisabledKey() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->disable($this->dataIdk);
        $client = array('idk' => $this->dataIdk);

        $result = $this->method->invoke($this->hazelnut, $client, $this->dataNut);
        $this->assertFalse($this->nutStore->isVerified($this->dataNut));
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED,
            $this->keyStore->getState($this->dataIdk)
        );
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result
        );
    }

    public function testIdentDisabledKeyWithWrongVuk() {
        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $newVuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));

        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->disable($this->dataIdk);
        $client = array(
            'idk' => $this->dataIdk,
            'suk' => $this->dataSuk,
            'vuk' => $newVuk
        );

        $result = $this->method->invoke($this->hazelnut, $client, $this->dataNut);
        $this->assertFalse($this->nutStore->isVerified($this->dataNut));
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED,
            $this->keyStore->getState($this->dataIdk)
        );
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result
        );
    }

    public function testIdentDisabledKeyWithCorrectVuk() {
        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $this->keyStore->disable($this->dataIdk);
        $client = array(
            'idk' => $this->dataIdk,
            'suk' => $this->dataSuk,
            'vuk' => $this->dataVuk
        );

        $result = $this->method->invoke($this->hazelnut, $client, $this->dataNut);
        $this->assertTrue($this->nutStore->isVerified($this->dataNut));
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE,
            $this->keyStore->getState($this->dataIdk)
        );
        $this->assertEquals(
            \Varden\Hazelnut\TIF_CID_MATCH,
            $result
        );
    }

    public function testIdentUnknownKeyWithoutSukVuk() {
        $client = array('idk' => $this->dataIdk);

        $result = $this->method->invoke($this->hazelnut, $client, $this->dataNut);
        $this->assertFalse($this->nutStore->isVerified($this->dataNut));
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN,
            $this->keyStore->getState($this->dataIdk)
        );
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result
        );
    }

    public function testIdentNewKey() {
        $client = array(
            'idk' => $this->dataIdk,
            'suk' => $this->dataSuk,
            'vuk' => $this->dataVuk
        );

        $result = $this->method->invoke($this->hazelnut, $client, $this->dataNut);
        $this->assertTrue($this->nutStore->isVerified($this->dataNut));
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE,
            $this->keyStore->getState($this->dataIdk)
        );
        $this->assertEquals(
            \Varden\Hazelnut\TIF_CID_MATCH,
            $result
        );
    }

    public function testMigrateNonexistantOldKey() {
        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $newIdk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));

        $client = array(
            'idk' => $newIdk,
            'suk' => $this->dataSuk,
            'vuk' => $this->dataVuk,
            'pidk' => $this->dataIdk
        );

        $result = $this->method->invoke($this->hazelnut, $client, $this->dataNut);
        $this->assertTrue($this->nutStore->isVerified($this->dataNut));
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN,
            $this->keyStore->getState($this->dataIdk)
        );
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE,
            $this->keyStore->getState($newIdk)
        );
        $this->assertEquals(
            \Varden\Hazelnut\TIF_CID_MATCH,
            $result
        );
    }

    public function testMigrateExistingOldKey() {
        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $newIdk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $newSuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $newVuk = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));

        $this->keyStore->create($this->dataIdk, $this->dataSuk, $this->dataVuk);
        $client = array(
            'idk' => $newIdk,
            'suk' => $newSuk,
            'vuk' => $newVuk,
            'pidk' => $this->dataIdk
        );

        $result = $this->method->invoke($this->hazelnut, $client, $this->dataNut);
        $this->assertTrue($this->nutStore->isVerified($this->dataNut));
        $this->assertEquals($newSuk, $this->keyStore->getSUK($newIdk));
        $this->assertEquals($newVuk, $this->keyStore->getVUK($newIdk));
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN,
            $this->keyStore->getState($this->dataIdk)
        );
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_ACTIVE,
            $this->keyStore->getState($newIdk)
        );
        $this->assertEquals(
            \Varden\Hazelnut\TIF_CID_MATCH |
            \Varden\Hazelnut\TIF_PID_MATCH,
            $result
        );
    }

    public function testInvalidKeyState() {
        $client = array('idk' => $this->dataIdk);

        $mockKey = $this->createStub('\Varden\Hazelnut\KeyStorage');
        $mockKey->method('getState')->with($this->equalTo($this->dataIdk))->willReturn(-1);
        $hazelnut = new \Varden\Hazelnut\Authenticator($mockKey, $this->nutStore);
        $this->expectException('Exception');
        $this->method->invoke($hazelnut, $client, $this->dataNut);
    }

}
