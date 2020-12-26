<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::createAuthSession
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 * @uses DummyNut
 * @uses DummyNutStorage
 */
class CoreCreateAuthSessionTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $keyStore;
    private $nutStore;

    protected function setUp() :void {
        require_once('tests/helpers/DummyKeyStorage.php');
        require_once('tests/helpers/DummyNutStorage.php');
        $this->keyStore = new DummyKeyStorage();
        $this->nutStore = new DummyNutStorage();
        $this->hazelnut = new \Varden\Hazelnut\Authenticator($this->keyStore, $this->nutStore);
        $this->hazelnut->setRemoteIP('2001:db8::1');
    }

    public function testCreateSession() {
        $result = $this->hazelnut->createAuthSession();
        $nut = $this->nutStore->retrieve($result);
        $this->assertNotNull($nut);
        $this->assertEquals(0, $nut->getTIF());
        $this->assertEquals('2001:0db8:0000:0000:0000:0000:0000:0001', $nut->getIP());
        $this->assertNull($nut->getIdentity());
    }
}
