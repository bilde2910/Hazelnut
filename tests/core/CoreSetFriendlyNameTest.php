<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::setFriendlyName
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreSetFriendlyNameTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $property;

    protected function setUp() :void {
        $class = new ReflectionClass('\Varden\Hazelnut\Authenticator');
        $this->hazelnut = $class->newInstanceWithoutConstructor();
        $this->property = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'params');
        $this->property->setAccessible(true);
        $this->property->setValue($this->hazelnut, array());
    }

    public function testPropertySet() {
        $this->hazelnut->setFriendlyName('Unit Test');
        $params = $this->property->getValue($this->hazelnut);
        $this->assertArrayHasKey('sfn', $params);
        $this->assertEquals('VW5pdCBUZXN0', $params['sfn']);
    }

    public function testProperReturnType() {
        $result = $this->hazelnut->setFriendlyName('Unit Test');
        $this->assertInstanceOf('\Varden\Hazelnut\Authenticator', $result);
    }

    public function testWrongParameterType() {
        $this->expectException('TypeError');
        $this->hazelnut->setFriendlyName(array());
    }
}
