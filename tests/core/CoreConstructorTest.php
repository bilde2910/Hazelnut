<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::__construct
 */
class CoreConstructorTest extends \PHPUnit\Framework\TestCase {
    private $keyStore;
    private $nutStore;
    private $propertySite;
    private $propertyAuthPath;
    private $propertySecure;
    private $propertyParams;
    private $propertyNutExpiry;
    private $propertyRemoteIP;

    protected function setUp() :void {
        $this->keyStore = new DummyKeyStorage();
        $this->nutStore = new DummyNutStorage();
        $this->propertySite = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'site');
        $this->propertySite->setAccessible(true);
        $this->propertyAuthPath = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'authPath');
        $this->propertyAuthPath->setAccessible(true);
        $this->propertySecure = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'secure');
        $this->propertySecure->setAccessible(true);
        $this->propertyParams = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'params');
        $this->propertyParams->setAccessible(true);
        $this->propertyNutExpiry = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'nutExpiry');
        $this->propertyNutExpiry->setAccessible(true);
        $this->propertyRemoteIP = new ReflectionProperty('\Varden\Hazelnut\Authenticator', 'remoteIP');
        $this->propertyRemoteIP->setAccessible(true);
    }

    public function testConstructorWithHostAndIpOnly() {
        $_SERVER = array(
            'HTTP_HOST' => 'example.com',
            'REMOTE_ADDR' => '2001:db8::1'
        );
        $hazelnut = new \Varden\Hazelnut\Authenticator($this->keyStore, $this->nutStore);

        $this->assertEquals('example.com', $this->propertySite->getValue($hazelnut));
        $this->assertIsString($this->propertyAuthPath->getValue($hazelnut));
        $this->assertFalse($this->propertySecure->getValue($hazelnut));
        $this->assertIsArray($this->propertyParams->getValue($hazelnut));
        $this->assertEmpty($this->propertyParams->getValue($hazelnut));
        $this->assertIsInt($this->propertyNutExpiry->getValue($hazelnut));
        $this->assertEquals('2001:db8::1', $this->propertyRemoteIP->getValue($hazelnut));
    }

    public function testConstructorWithHttpsOn() {
        $_SERVER = array(
            'HTTP_HOST' => 'example.com',
            'REMOTE_ADDR' => '2001:db8::1',
            'HTTPS' => 'on'
        );
        $hazelnut = new \Varden\Hazelnut\Authenticator($this->keyStore, $this->nutStore);

        $this->assertEquals('example.com', $this->propertySite->getValue($hazelnut));
        $this->assertIsString($this->propertyAuthPath->getValue($hazelnut));
        $this->assertTrue($this->propertySecure->getValue($hazelnut));
        $this->assertIsArray($this->propertyParams->getValue($hazelnut));
        $this->assertEmpty($this->propertyParams->getValue($hazelnut));
        $this->assertIsInt($this->propertyNutExpiry->getValue($hazelnut));
        $this->assertEquals('2001:db8::1', $this->propertyRemoteIP->getValue($hazelnut));
    }

    public function testConstructorWithHttpsOff() {
        $_SERVER = array(
            'HTTP_HOST' => 'example.com',
            'REMOTE_ADDR' => '2001:db8::1',
            'HTTPS' => 'off'
        );
        $hazelnut = new \Varden\Hazelnut\Authenticator($this->keyStore, $this->nutStore);

        $this->assertEquals('example.com', $this->propertySite->getValue($hazelnut));
        $this->assertIsString($this->propertyAuthPath->getValue($hazelnut));
        $this->assertFalse($this->propertySecure->getValue($hazelnut));
        $this->assertIsArray($this->propertyParams->getValue($hazelnut));
        $this->assertEmpty($this->propertyParams->getValue($hazelnut));
        $this->assertIsInt($this->propertyNutExpiry->getValue($hazelnut));
        $this->assertEquals('2001:db8::1', $this->propertyRemoteIP->getValue($hazelnut));
    }
}
