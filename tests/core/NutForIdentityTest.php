<?php
/**
 * @covers \Varden\Hazelnut\Nut::forIdentity
 * @covers \Varden\Hazelnut\Nut::getIdentity
 * @uses \Varden\Hazelnut\Nut::__construct
 */
class NutForIdentityTest extends \PHPUnit\Framework\TestCase {
    private $nut;

    protected function setUp() :void {
        $this->nut = new \Varden\Hazelnut\Nut('sample');
    }

    public function testStoreKeyAndFetch() {
        $key = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());
        $this->nut->forIdentity($key);
        $this->assertEquals($key, $this->nut->getIdentity());
    }

    public function testStoreNullAndFetch() {
        $this->nut->forIdentity(null);
        $this->assertNull($this->nut->getIdentity());
    }
}
