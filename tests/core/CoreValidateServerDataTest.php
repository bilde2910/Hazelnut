<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::validateServerData
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 */
class CoreValidateServerDataTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $method;
    private $data;

    protected function setUp() :void {
        $class = new ReflectionClass('\Varden\Hazelnut\Authenticator');
        $this->hazelnut = $class->newInstanceWithoutConstructor()
            -> setSite('example.com')
            -> setAuthPath('/sqrlauth.php')
            -> setSecure(true);

        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'validateServerData');
        $this->method->setAccessible(true);

        $this->data = new \Varden\Hazelnut\Nut('sample');
        $this->data
            -> createdAt(time())
            -> forIdentity(null)
            -> withTIF('0')
            -> byIP('2001:db8::1');
    }

    public function testValidServerString() {
        $server = 'sqrl://example.com/sqrlauth.php?nut=sample';
        $result = $this->method->invoke($this->hazelnut, $server, $this->data);
        $this->assertTrue($result);
    }

    public function testValidServerArray() {
        $server = array(
            'ver' => '1',
            'nut' => 'sample',
            'tif' => '0',
            'qry' => '/sqrlauth.php?nut=sample'
        );
        $result = $this->method->invoke($this->hazelnut, $server, $this->data);
        $this->assertTrue($result);
    }

    public function testMissingServerFields() {
        $server = array(
            'ver' => '1',
            'nut' => 'sample'
        );
        $result = $this->method->invoke($this->hazelnut, $server, $this->data);
        $this->assertFalse($result);
    }

    public function testWrongTif() {
        $server = array(
            'ver' => '1',
            'nut' => 'sample',
            'tif' => '192',
            'qry' => '/sqrlauth.php?nut=sample'
        );
        $result = $this->method->invoke($this->hazelnut, $server, $this->data);
        $this->assertFalse($result);
    }

    public function testWrongNut() {
        $server = array(
            'ver' => '1',
            'nut' => 'wrong',
            'tif' => '0',
            'qry' => '/sqrlauth.php?nut=sample'
        );
        $result = $this->method->invoke($this->hazelnut, $server, $this->data);
        $this->assertFalse($result);
    }

    public function testWrongQry() {
        $server = array(
            'ver' => '1',
            'nut' => 'sample',
            'tif' => '0',
            'qry' => '/incorrect.php?nut=sample'
        );
        $result = $this->method->invoke($this->hazelnut, $server, $this->data);
        $this->assertFalse($result);
    }
}
