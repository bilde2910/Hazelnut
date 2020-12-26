<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::toFullIPv6Address
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreToFullIPv6AddressTest extends \PHPUnit\Framework\TestCase {
    private $method;

    protected function setUp() :void {
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'toFullIPv6Address');
        $this->method->setAccessible(true);
    }

    public function testIpv4ToIpv6Translation() {
        $result = $this->method->invoke(null, '127.0.0.1');
        $this->assertEquals('0000:0000:0000:0000:0000:ffff:7f00:0001', $result);
    }

    public function testFullIpv6Address() {
        $result = $this->method->invoke(null, '2001:0db8:0123:4567:89ab:cdef:0123:abcd');
        $this->assertEquals('2001:0db8:0123:4567:89ab:cdef:0123:abcd', $result);
    }

    public function testZeroPadding() {
        $result = $this->method->invoke(null, '2001:db8:0:18:cd90:ace:fade:beef');
        $this->assertEquals('2001:0db8:0000:0018:cd90:0ace:fade:beef', $result);
    }

    public function testDoubleColonExpansion() {
        $result = $this->method->invoke(null, '2001:db8::fade:beef');
        $this->assertEquals('2001:0db8:0000:0000:0000:0000:fade:beef', $result);
    }

    public function testIpv6Localhost() {
        $result = $this->method->invoke(null, '::1');
        $this->assertEquals('0000:0000:0000:0000:0000:0000:0000:0001', $result);
    }

    public function testIpv6Wildcard() {
        $result = $this->method->invoke(null, '::');
        $this->assertEquals('0000:0000:0000:0000:0000:0000:0000:0000', $result);
    }
}
