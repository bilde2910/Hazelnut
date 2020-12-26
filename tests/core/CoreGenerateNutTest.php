<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::generateNut
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 * @uses DummyNut
 * @uses DummyNutStorage
 */
class CoreGenerateNutTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $keyStore;
    private $nutStore;
    private $method;

    private $dataKey;

    protected function setUp() :void {
        $this->keyStore = new DummyKeyStorage();
        $this->nutStore = new DummyNutStorage();
        $this->hazelnut = new \Varden\Hazelnut\Authenticator($this->keyStore, $this->nutStore);
        $this->hazelnut->setRemoteIP('2001:db8::1');

        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'generateNut');
        $this->method->setAccessible(true);

        $encode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $encode->setAccessible(true);
        $this->dataKey = $encode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
    }

    public function testDepositNut() {
        $result = $this->method->invoke($this->hazelnut, 192, $this->dataKey);
        $nut = $this->nutStore->retrieve($result);
        $this->assertNotNull($nut);
        $this->assertEquals(192, $nut->getTIF());
        $this->assertEquals('2001:0db8:0000:0000:0000:0000:0000:0001', $nut->getIP());
        $this->assertEquals($this->dataKey, $nut->getIdentity());
    }

    public function testReplaceNut() {
        $old = $this->method->invoke($this->hazelnut);
        $result = $this->method->invoke($this->hazelnut, 192, $this->dataKey, $old);
        $this->assertNull($this->nutStore->retrieve($old));
        $nut = $this->nutStore->retrieve($result);
        $this->assertNotNull($nut);
        $this->assertEquals(192, $nut->getTIF());
        $this->assertEquals('2001:0db8:0000:0000:0000:0000:0000:0001', $nut->getIP());
        $this->assertEquals($this->dataKey, $nut->getIdentity());
    }
}
