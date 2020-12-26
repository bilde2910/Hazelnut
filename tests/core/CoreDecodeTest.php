<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::decode
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreDecodeTest extends \PHPUnit\Framework\TestCase {
    private $method;

    protected function setUp() :void {
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'decode');
        $this->method->setAccessible(true);
    }

    public function testBasicString() {
        $result = $this->method->invoke(null, 'VGhpcyBpcyBhIHRlc3Qgd2l0aCBubyBwYWRkaW5n');
        $this->assertEquals('This is a test with no padding', $result);
    }

    public function testWithoutPadding() {
        $result = $this->method->invoke(null, 'VGhpcyBpcyBhIHBhZGRlZCBzdHJpbmcgdGVzdA');
        $this->assertEquals('This is a padded string test', $result);
    }

    public function testUrlSafeSubstitution() {
        $result = $this->method->invoke(null, 'ABC-DEF_GHIJ');
        $this->assertEquals(base64_decode('ABC+DEF/GHIJ'), $result);
    }
}
