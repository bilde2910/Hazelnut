<?php
/**
 * @covers DummyNut
 */
class DummyNutTest extends \PHPUnit\Framework\TestCase {
    public function testConstructorDefault() {
        $nut = new DummyNut('2001:db8::1', 192, 'pubkey', 'sample');
        $this->assertGreaterThan(time() - 1, $nut->created);
        $this->assertLessThan(time() + 1, $nut->created);
        $this->assertEquals('2001:db8::1', $nut->ip);
        $this->assertEquals(192, $nut->tif);
        $this->assertEquals('pubkey', $nut->pubkey);
        $this->assertEquals('sample', $nut->orig);
        $this->assertFalse($nut->verified);
    }

    public function testConstructorVerified() {
        $nut = new DummyNut('2001:db8::1', 192, 'pubkey', 'sample', true);
        $this->assertGreaterThan(time() - 1, $nut->created);
        $this->assertLessThan(time() + 1, $nut->created);
        $this->assertEquals('2001:db8::1', $nut->ip);
        $this->assertEquals(192, $nut->tif);
        $this->assertEquals('pubkey', $nut->pubkey);
        $this->assertEquals('sample', $nut->orig);
        $this->assertTrue($nut->verified);
    }

    public function testConstructorUnverified() {
        $nut = new DummyNut('2001:db8::1', 192, 'pubkey', 'sample', false);
        $this->assertGreaterThan(time() - 1, $nut->created);
        $this->assertLessThan(time() + 1, $nut->created);
        $this->assertEquals('2001:db8::1', $nut->ip);
        $this->assertEquals(192, $nut->tif);
        $this->assertEquals('pubkey', $nut->pubkey);
        $this->assertEquals('sample', $nut->orig);
        $this->assertFalse($nut->verified);
    }

    public function testConstructorCreated() {
        $nut = new DummyNut('2001:db8::1', 192, 'pubkey', 'sample', false, 10240);
        $this->assertEquals(10240, $nut->created);
        $this->assertEquals('2001:db8::1', $nut->ip);
        $this->assertEquals(192, $nut->tif);
        $this->assertEquals('pubkey', $nut->pubkey);
        $this->assertEquals('sample', $nut->orig);
        $this->assertFalse($nut->verified);
    }
}
