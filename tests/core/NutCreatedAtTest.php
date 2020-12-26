<?php
/**
 * @covers \Varden\Hazelnut\Nut::createdAt
 * @covers \Varden\Hazelnut\Nut::getCreatedTime
 * @uses \Varden\Hazelnut\Nut::__construct
 */
class NutCreatedAtTest extends \PHPUnit\Framework\TestCase {
    private $nut;

    protected function setUp() :void {
        $this->nut = new \Varden\Hazelnut\Nut('sample');
    }

    public function testStoreAndFetch() {
        $time = time();
        $this->nut->createdAt($time);
        $this->assertEquals($time, $this->nut->getCreatedTime());
    }
}
