<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::isAuthenticated
 * @uses \Varden\Hazelnut\Authenticator
 * @uses DummyKey
 * @uses DummyKeyStorage
 * @uses DummyNut
 * @uses DummyNutStorage
 */
class CoreIsAuthenticatedTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $keyStore;
    private $nutStore;

    protected function setUp() :void {
        $this->keyStore = new DummyKeyStorage();
        $this->nutStore = new DummyNutStorage();
        $this->hazelnut = new \Varden\Hazelnut\Authenticator($this->keyStore, $this->nutStore);
    }

    public function testMissingNut() {
        $result = $this->hazelnut->isAuthenticated('sample');
        $this->assertFalse($result);
    }

    public function testUnverifiedNut() {
        $this->nutStore->deposit('sample', '2001:db8::1', \Varden\Hazelnut\TIF_CID_MATCH, null);
        $result = $this->hazelnut->isAuthenticated('sample');
        $this->assertFalse($result);
    }

    public function testVerifiedNut() {
        $this->nutStore->deposit('sample', '2001:db8::1', \Varden\Hazelnut\TIF_CID_MATCH, null);
        $this->nutStore->markVerified('sample');
        $result = $this->hazelnut->isAuthenticated('sample');
        $this->assertTrue($result);
    }

    public function testVerifiedReplacedNut() {
        $this->nutStore->deposit('sample', '2001:db8::1', \Varden\Hazelnut\TIF_CID_MATCH, null);
        $this->nutStore->replace('sample', 'replaced', '2001:db8::1', \Varden\Hazelnut\TIF_CID_MATCH, null);
        $this->nutStore->markVerified('replaced');
        $result = $this->hazelnut->isAuthenticated('sample');
        $this->assertTrue($result);
    }
}
