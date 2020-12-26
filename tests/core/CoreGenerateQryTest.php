<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::generateQry
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreGenerateQryTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $method;

    protected function setUp() :void {
        $class = new ReflectionClass('\Varden\Hazelnut\Authenticator');
        $this->hazelnut = $class->newInstanceWithoutConstructor()
            -> setSite('example.com')
            -> setAuthPath('/sqrlauth.php')
            -> setSecure(true);

        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'generateQry');
        $this->method->setAccessible(true);
    }

    public function testGenerateQry() {
        $result = $this->method->invoke($this->hazelnut, 'sample');
        $this->assertEquals('/sqrlauth.php?nut=sample', $result);
    }
}
