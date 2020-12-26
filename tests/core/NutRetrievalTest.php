<?php
/**
 * @covers \Varden\Hazelnut\Nut::getNut
 * @covers \Varden\Hazelnut\Nut::__construct
 */
class NutRetrievalTest extends \PHPUnit\Framework\TestCase {
    private $nut;

    protected function setUp() :void {
        $this->nut = new \Varden\Hazelnut\Nut('sample');
    }

    public function testFetch() {
        $this->assertEquals('sample', $this->nut->getNut());
    }
}
