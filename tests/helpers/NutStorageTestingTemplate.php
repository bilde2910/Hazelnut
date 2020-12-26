<?php
abstract class NutStorageTestingTemplate extends \PHPUnit\Framework\TestCase {
    private $storage;
    private $nut;

    const REMOTE_IP = '2001:0db8:0000:0000:0000:0000:0000:0001';
    const ALTERNATE_IP = '2001:0db8:1111:1111:1111:1111:1111:1112';

    protected function configure(\Varden\Hazelnut\NutStorage $storage) :void {
        require_once('tests/helpers/DummyKeyStorage.php');
        require_once('tests/helpers/DummyNutStorage.php');
        $hazelnut = new \Varden\Hazelnut\Authenticator(new DummyKeyStorage(), new DummyNutStorage());
        $hazelnut->setRemoteIP(self::REMOTE_IP);
        $this->nut = $hazelnut->createAuthSession();
        $this->storage = $storage;
    }

    protected function destroy() :void {
        $this->storage = null;
    }

    public function testRetrieveNonexistentNut() {
        $result = $this->storage->retrieve($this->nut);
        $this->assertNull($result);
    }

    public function testRetrieveNullKeyNut() {
        $this->storage->deposit($this->nut, self::REMOTE_IP, 192, null);
        $result = $this->storage->retrieve($this->nut);
        $this->assertInstanceOf('\Varden\Hazelnut\Nut', $result);
        $this->assertEquals($this->nut, $result->getNut());
        $this->assertGreaterThan(time() - 5, $result->getCreatedTime());
        $this->assertLessThan(time() + 5, $result->getCreatedTime());
        $this->assertNull($result->getIdentity());
        $this->assertEquals(192, $result->getTIF());
        $this->assertEquals(self::REMOTE_IP, $result->getIP());
    }

    public function testRetrieveDefinedKeyNut() {
        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $pubkey = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));

        $this->storage->deposit($this->nut, self::REMOTE_IP, 192, $pubkey);
        $result = $this->storage->retrieve($this->nut);
        $this->assertInstanceOf('\Varden\Hazelnut\Nut', $result);
        $this->assertEquals($this->nut, $result->getNut());
        $this->assertGreaterThan(time() - 5, $result->getCreatedTime());
        $this->assertLessThan(time() + 5, $result->getCreatedTime());
        $this->assertEquals($pubkey, $result->getIdentity());
        $this->assertEquals(192, $result->getTIF());
        $this->assertEquals(self::REMOTE_IP, $result->getIP());
    }

    public function testNotVerifiedAndNoNut() {
        $this->assertFalse($this->storage->isVerified($this->nut));
    }

    public function testNotVerified() {
        $this->storage->deposit($this->nut, self::REMOTE_IP, 192, null);
        $this->assertFalse($this->storage->isVerified($this->nut));
    }

    public function testSelfVerified() {
        $this->storage->deposit($this->nut, self::REMOTE_IP, 192, null);
        $this->storage->markVerified($this->nut);
        $this->assertTrue($this->storage->isVerified($this->nut));
    }

    public function testParentVerified() {
        $this->storage->deposit($this->nut, self::REMOTE_IP, 192, null);
        $this->storage->replace($this->nut, 'sample', self::REMOTE_IP, 192, null);
        $this->storage->markVerified('sample');
        $this->assertTrue($this->storage->isVerified($this->nut));
    }

    public function testReplaceWithNewNullKeyNut() {
        $hazelnut = new \Varden\Hazelnut\Authenticator(new DummyKeyStorage(), new DummyNutStorage());
        $hazelnut->setRemoteIP(self::REMOTE_IP);
        $newNut = $hazelnut->createAuthSession();

        $this->storage->deposit($this->nut, self::REMOTE_IP, 192, null);
        $this->storage->replace($this->nut, $newNut, self::ALTERNATE_IP, 64, null);
        $this->assertNull($this->storage->retrieve($this->nut));
        $result = $this->storage->retrieve($newNut);
        $this->assertInstanceOf('\Varden\Hazelnut\Nut', $result);
        $this->assertEquals($newNut, $result->getNut());
        $this->assertGreaterThan(time() - 5, $result->getCreatedTime());
        $this->assertLessThan(time() + 5, $result->getCreatedTime());
        $this->assertNull($result->getIdentity());
        $this->assertEquals(64, $result->getTIF());
        $this->assertEquals(self::ALTERNATE_IP, $result->getIP());
    }

    public function testReplaceWithNewDefinedKeyNut() {
        $hazelnut = new \Varden\Hazelnut\Authenticator(new DummyKeyStorage(), new DummyNutStorage());
        $hazelnut->setRemoteIP(self::REMOTE_IP);
        $newNut = $hazelnut->createAuthSession();
        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $newKey = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));

        $this->storage->deposit($this->nut, self::REMOTE_IP, 192, null);
        $this->storage->replace($this->nut, $newNut, self::ALTERNATE_IP, 64, $newKey);
        $this->assertNull($this->storage->retrieve($this->nut));
        $result = $this->storage->retrieve($newNut);
        $this->assertInstanceOf('\Varden\Hazelnut\Nut', $result);
        $this->assertEquals($newNut, $result->getNut());
        $this->assertGreaterThan(time() - 5, $result->getCreatedTime());
        $this->assertLessThan(time() + 5, $result->getCreatedTime());
        $this->assertEquals($newKey, $result->getIdentity());
        $this->assertEquals(64, $result->getTIF());
        $this->assertEquals(self::ALTERNATE_IP, $result->getIP());
    }

    public function testMarkVerified() {
        $this->storage->deposit($this->nut, self::REMOTE_IP, 192, null);
        $this->assertFalse($this->storage->isVerified($this->nut));
        $this->storage->markVerified($this->nut);
        $this->assertTrue($this->storage->isVerified($this->nut));
    }

    public function testDestroy() {
        $this->storage->deposit($this->nut, self::REMOTE_IP, 192, null);
        $this->storage->destroy($this->nut);
        $this->assertNull($this->storage->retrieve($this->nut));
    }

}
