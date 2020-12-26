<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::fail
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreFailTest extends \PHPUnit\Framework\TestCase {
    private $method;

    protected function setUp() :void {
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'fail');
        $this->method->setAccessible(true);
    }

    public function testDefaultCause() {
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $this->method->invoke(null)
        );
    }

    public function testSpecificCause() {
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_MISMATCHING_NUT_ID,
            $this->method->invoke(null, \Varden\Hazelnut\TIF_MISMATCHING_NUT_ID)
        );
    }
}
