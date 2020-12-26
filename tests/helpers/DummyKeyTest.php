<?php
/**
 * @covers DummyKey
 */
class DummyKeyTest extends \PHPUnit\Framework\TestCase {
    public function testConstructorDefault() {
        $nut = new DummyKey('suk', 'vuk');
        $this->assertEquals('suk', $nut->suk);
        $this->assertEquals('vuk', $nut->vuk);
        $this->assertTrue($nut->enabled);
    }

    public function testConstructorDisabled() {
        $nut = new DummyKey('suk', 'vuk', false);
        $this->assertEquals('suk', $nut->suk);
        $this->assertEquals('vuk', $nut->vuk);
        $this->assertFalse($nut->enabled);
    }

    public function testConstructorEnabled() {
        $nut = new DummyKey('suk', 'vuk', true);
        $this->assertEquals('suk', $nut->suk);
        $this->assertEquals('vuk', $nut->vuk);
        $this->assertTrue($nut->enabled);
    }
}
