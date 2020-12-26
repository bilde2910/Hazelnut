<?php
/**
 * @covers \Varden\Hazelnut\Nut::withTIF
 * @covers \Varden\Hazelnut\Nut::getTIF
 * @uses \Varden\Hazelnut\Nut::__construct
 */
class NutWithTifTest extends \PHPUnit\Framework\TestCase {
    private $nut;

    protected function setUp() :void {
        $this->nut = new \Varden\Hazelnut\Nut('sample');
    }

    public function testStoreAndFetch() {
        $this->nut->withTIF(192);
        $this->assertEquals(192, $this->nut->getTIF());
    }
}
