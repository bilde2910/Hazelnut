<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::getSqrlUri
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreGetSqrlUriTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;

    protected function setUp() :void {
        $class = new ReflectionClass('\Varden\Hazelnut\Authenticator');
        $this->hazelnut = $class->newInstanceWithoutConstructor();
    }

    public function testGenerateSqrlUri() {
        $this->hazelnut
            -> setSite('example.com')
            -> setAuthPath('/sqrlauth.php')
            -> setSecure(true);
        $result = $this->hazelnut->getSqrlUri('sample');
        $this->assertEquals('sqrl://example.com/sqrlauth.php?nut=sample', $result);
    }

    public function testGenerateQrlUri() {
        $this->hazelnut
            -> setSite('example.com')
            -> setAuthPath('/sqrlauth.php')
            -> setSecure(false);
        $result = $this->hazelnut->getSqrlUri('sample');
        $this->assertEquals('qrl://example.com/sqrlauth.php?nut=sample', $result);
    }

    public function testWithFriendlyName() {
        $this->hazelnut
            -> setSite('example.com')
            -> setAuthPath('/sqrlauth.php')
            -> setSecure(true)
            -> setFriendlyName('Unit Test');
        $result = $this->hazelnut->getSqrlUri('sample');
        $this->assertEquals('sqrl://example.com/sqrlauth.php?sfn=VW5pdCBUZXN0&nut=sample', $result);
    }

    public function testWithSubpathSite() {
        $this->hazelnut
            -> setSite('example.com/app/sqrl')
            -> setAuthPath('/sqrlauth.php')
            -> setSecure(true);
        $result = $this->hazelnut->getSqrlUri('sample');
        $this->assertEquals('sqrl://example.com/app/sqrl/sqrlauth.php?x=9&nut=sample', $result);
    }
}
