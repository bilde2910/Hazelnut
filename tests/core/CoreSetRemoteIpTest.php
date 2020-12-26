<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::setRemoteIP
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreSetRemoteIpTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $property;

    protected function setUp() :void {
        $class = new ReflectionClass('\Varden\Hazelnut\Authenticator');
        $this->hazelnut = $class->newInstanceWithoutConstructor();
        $this->property = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'remoteIP');
        $this->property->setAccessible(true);
        $this->property->setValue($this->hazelnut, '');
    }

    public function testPropertySet() {
        $this->hazelnut->setRemoteIP('2001:db8::1');
        $this->assertEquals('2001:db8::1', $this->property->getValue($this->hazelnut));
    }

    public function testProperReturnType() {
        $result = $this->hazelnut->setRemoteIP('2001:db8::1');
        $this->assertInstanceOf('\Varden\Hazelnut\Authenticator', $result);
    }

    public function testWrongParameterType() {
        $this->expectException('TypeError');
        $this->hazelnut->setRemoteIP(array());
    }
}
