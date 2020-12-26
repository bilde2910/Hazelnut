<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::setSecure
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreSetSecureTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $property;

    protected function setUp() :void {
        $class = new ReflectionClass('\Varden\Hazelnut\Authenticator');
        $this->hazelnut = $class->newInstanceWithoutConstructor();
        $this->property = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'secure');
        $this->property->setAccessible(true);
        $this->property->setValue($this->hazelnut, false);
    }

    public function testPropertySet() {
        $this->hazelnut->setSecure(true);
        $this->assertTrue($this->property->getValue($this->hazelnut));
    }

    public function testProperReturnType() {
        $result = $this->hazelnut->setSecure(true);
        $this->assertInstanceOf('\Varden\Hazelnut\Authenticator', $result);
    }

    public function testWrongParameterType() {
        $this->expectException('TypeError');
        $this->hazelnut->setSecure(array());
    }
}
