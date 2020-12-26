<?php
/**
 * @covers DummyNutStorage
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 * @uses DummyNut
 */
class DummyNutStorageTest extends NutStorageTestingTemplate {
    private $storage;

    protected function setUp() :void {
        require_once('tests/helpers/DummyNutStorage.php');
        $this->configure($this->storage = new DummyNutStorage());
    }

    protected function tearDown() :void {
        $this->destroy();
    }

    public function testForceSetNutCreated() {
        $this->storage->deposit('sample', '2001:db8::1', 192, null);
        $this->storage->forceSetNutCreated('sample', 10240);
        $this->assertEquals(10240, $this->storage->retrieve('sample')->getCreatedTime());
    }

    public function testForceSetNutPubkey() {
        $this->storage->deposit('sample', '2001:db8::1', 192, null);
        $this->storage->forceSetNutPubkey('sample', 'pubkey');
        $this->assertEquals('pubkey', $this->storage->retrieve('sample')->getIdentity());
    }

    public function testForceSetNutIp() {
        $this->storage->deposit('sample', '2001:db8::1', 192, null);
        $this->storage->forceSetNutIP('sample', '2001:db8::2');
        $this->assertEquals('2001:db8::2', $this->storage->retrieve('sample')->getIP());
    }

    public function testForceGetOriginal() {
        $this->storage->deposit('sample', '2001:db8::1', 192, null);
        $this->storage->replace('sample', 'new', '2001:db8::1', 192, null);
        $this->assertEquals('sample', $this->storage->forceGetOriginal('new'));
    }
}
