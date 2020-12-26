<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::setExpiryMinutes
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreSetExpiryMinutesTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $property;

    protected function setUp() :void {
        $class = new ReflectionClass('\Varden\Hazelnut\Authenticator');
        $this->hazelnut = $class->newInstanceWithoutConstructor();
        $this->property = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'nutExpiry');
        $this->property->setAccessible(true);
        $this->property->setValue($this->hazelnut, 5);
    }

    public function testPropertySet() {
        $this->hazelnut->setExpiryMinutes(10);
        $this->assertEquals(10, $this->property->getValue($this->hazelnut));
    }

    public function testProperReturnType() {
        $result = $this->hazelnut->setExpiryMinutes(10);
        $this->assertInstanceOf('\Varden\Hazelnut\Authenticator', $result);
    }

    public function testWrongParameterType() {
        $this->expectException('TypeError');
        $this->hazelnut->setExpiryMinutes(array());
    }
}
