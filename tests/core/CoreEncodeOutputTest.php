<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::encodeOutput
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreEncodeOutputTest extends \PHPUnit\Framework\TestCase {
    private $method;

    protected function setUp() :void {
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encodeOutput');
        $this->method->setAccessible(true);
    }

    public function testEncodeArray() {
        $result = $this->method->invoke(null, array(
            'ver' => '1',
            'nut' => 'sample',
            'tif' => '0'
        ));
        $this->assertEquals('dmVyPTENCm51dD1zYW1wbGUNCnRpZj0w', $result);
    }
}
