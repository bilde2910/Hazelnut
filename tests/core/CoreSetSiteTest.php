<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::setSite
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreSetSiteTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $propertySite;
    private $propertyParams;

    protected function setUp() :void {
        $class = new ReflectionClass('\Varden\Hazelnut\Authenticator');
        $this->hazelnut = $class->newInstanceWithoutConstructor();
        $this->propertySite = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'site');
        $this->propertySite->setAccessible(true);
        $this->propertySite->setValue($this->hazelnut, '');
        $this->propertyParams = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'params');
        $this->propertyParams->setAccessible(true);
        $this->propertyParams->setValue($this->hazelnut, array());
    }

    public function testSetDomainOnly() {
        $this->hazelnut->setSite('example.com');
        $this->assertEquals('example.com', $this->propertySite->getValue($this->hazelnut));
        $this->assertEmpty($this->propertyParams->getValue($this->hazelnut));
    }

    public function testSetDomainAndPath() {
        $this->hazelnut->setSite('example.org/app/sqrl');
        $this->assertEquals('example.org/app/sqrl', $this->propertySite->getValue($this->hazelnut));
        $params = $this->propertyParams->getValue($this->hazelnut);
        $this->assertArrayHasKey('x', $params);
        $this->assertEquals(9, $params['x']);
    }

    public function testProperReturnType() {
        $result = $this->hazelnut->setSite('example.com');
        $this->assertInstanceOf('\Varden\Hazelnut\Authenticator', $result);
    }

    public function testWrongParameterType() {
        $this->expectException('TypeError');
        $this->hazelnut->setSite(array());
    }
}
