<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::setAuthPath
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreSetAuthPathTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $property;

    protected function setUp() :void {
        $class = new ReflectionClass('\Varden\Hazelnut\Authenticator');
        $this->hazelnut = $class->newInstanceWithoutConstructor();
        $this->property = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'authPath');
        $this->property->setAccessible(true);
        $this->property->setValue($this->hazelnut, '');
    }

    public function testPropertySet() {
        $this->hazelnut->setAuthPath('/sqrlauth.php');
        $this->assertEquals('/sqrlauth.php', $this->property->getValue($this->hazelnut));
    }

    public function testProperReturnType() {
        $result = $this->hazelnut->setAuthPath('/sqrlauth.php');
        $this->assertInstanceOf('\Varden\Hazelnut\Authenticator', $result);
    }

    public function testWrongParameterType() {
        $this->expectException('TypeError');
        $this->hazelnut->setAuthPath(array());
    }
}
