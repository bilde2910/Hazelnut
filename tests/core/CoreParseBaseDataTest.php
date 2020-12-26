<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::parseBaseData
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreParseBaseDataTest extends \PHPUnit\Framework\TestCase {
    private $method;

    protected function setUp() :void {
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'parseBaseData');
        $this->method->setAccessible(true);
    }

    public function testSqrlUri() {
        $result = $this->method->invoke(null, 'c3FybDovL2V4YW1wbGUuY29tL3NxcmxhdXRoLnBocD9udXQ9c2FtcGxl');
        $this->assertIsString($result);
        $this->assertEquals('sqrl://example.com/sqrlauth.php?nut=sample', $result);
    }

    public function testQrlUri() {
        $result = $this->method->invoke(null, 'cXJsOi8vZXhhbXBsZS5jb20vc3FybGF1dGgucGhwP251dD1zYW1wbGU');
        $this->assertIsString($result);
        $this->assertEquals('qrl://example.com/sqrlauth.php?nut=sample', $result);
    }

    public function testArrayPayload() {
        $result = $this->method->invoke(null, 'dmVyPTENCm51dD1zYW1wbGUNCnRpZj0w');
        $this->assertIsArray($result);
        $this->assertEquals(array(
            'ver' => '1',
            'nut' => 'sample',
            'tif' => '0'
        ), $result);
    }
}
