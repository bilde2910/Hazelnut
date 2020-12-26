<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::ensureValuesSet
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreEnsureValuesSetTest extends \PHPUnit\Framework\TestCase {
    private $method;
    private $data;

    protected function setUp() :void {
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'ensureValuesSet');
        $this->method->setAccessible(true);
        $this->data = array(
            'ver' => '1',
            'nut' => 'sample',
            'tif' => '0'
        );
    }

    public function testSingleKeyFound() {
        $result = $this->method->invoke(null, $this->data, 'tif');
        $this->assertTrue($result);
    }

    public function testMultipleKeysFound() {
        $result = $this->method->invoke(null, $this->data, 'tif', 'ver');
        $this->assertTrue($result);
    }

    public function testSingleKeyMissing() {
        $result = $this->method->invoke(null, $this->data, 'qry');
        $this->assertFalse($result);
    }

    public function testMultipleKeysMissing() {
        $result = $this->method->invoke(null, $this->data, 'qry', 'idk');
        $this->assertFalse($result);
    }

    public function testMixed() {
        $result = $this->method->invoke(null, $this->data, 'tif', 'qry');
        $this->assertFalse($result);
    }

    public function testEmptyString() {
        $result = $this->method->invoke(null, array('tif' => ''), 'tif');
        $this->assertFalse($result);
    }
}
