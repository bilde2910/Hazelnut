<?php
/**
 * @covers \Varden\Hazelnut\Nut::byIP
 * @covers \Varden\Hazelnut\Nut::getIP
 * @uses \Varden\Hazelnut\Nut::__construct
 */
class NutByIpTest extends \PHPUnit\Framework\TestCase {
    private $nut;

    protected function setUp() :void {
        $this->nut = new \Varden\Hazelnut\Nut('sample');
    }

    public function testStoreAndFetch() {
        $this->nut->byIP('2001:db8::1');
        $this->assertEquals('2001:db8::1', $this->nut->getIP());
    }
}
