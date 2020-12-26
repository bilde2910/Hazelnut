<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::encode
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreEncodeTest extends \PHPUnit\Framework\TestCase {
    private $method;

    protected function setUp() :void {
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $this->method->setAccessible(true);
    }

    public function testBasicString() {
        $result = $this->method->invoke(null, 'This is a test with no padding');
        $this->assertEquals('VGhpcyBpcyBhIHRlc3Qgd2l0aCBubyBwYWRkaW5n', $result);
    }

    public function testRemovePadding() {
        $result = $this->method->invoke(null, 'This is a padded string test');
        $this->assertEquals('VGhpcyBpcyBhIHBhZGRlZCBzdHJpbmcgdGVzdA', $result);
    }

    public function testUrlSafeSubstitution() {
        $result = $this->method->invoke(null, base64_decode('ABC+DEF/GHIJ'));
        $this->assertEquals('ABC-DEF_GHIJ', $result);
    }
}
