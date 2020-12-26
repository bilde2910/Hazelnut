<?php
/**
 * @covers DummyKeyStorage
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 * @uses DummyKey
 */
class DummyKeyStorageTest extends KeyStorageTestingTemplate {
    protected function setUp() :void {
        require_once('tests/helpers/DummyKeyStorage.php');
        $this->configure(new DummyKeyStorage());
    }

    protected function tearDown() :void {
        $this->destroy();
    }
}
