<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::validateNut
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 */
class CoreValidateNutTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $method;

    protected function setUp() :void {
        $class = new ReflectionClass('\Varden\Hazelnut\Authenticator');
        $this->hazelnut = $class->newInstanceWithoutConstructor()
            -> setExpiryMinutes(5);

        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'validateNut');
        $this->method->setAccessible(true);
    }

    public function testValidNutWithNullKey() {
        $nut = new \Varden\Hazelnut\Nut('sample');
        $nut
            -> createdAt(time())
            -> forIdentity($key = null)
            -> withTIF('0')
            -> byIP('2001:db8::1');
        $result = $this->method->invoke($this->hazelnut, $nut, $key);
        $this->assertEquals(\Varden\Hazelnut\NUT_VALID, $result);
    }

    public function testValidNutWithDefinedKey() {
        $nut = new \Varden\Hazelnut\Nut('sample');
        $nut
            -> createdAt(time())
            -> forIdentity($key = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()))
            -> withTIF('0')
            -> byIP('2001:db8::1');
        $result = $this->method->invoke($this->hazelnut, $nut, $key);
        $this->assertEquals(\Varden\Hazelnut\NUT_VALID, $result);
    }

    public function testValidNutWithPaddedDefinedKey() {
        /*
         * Per https://www.grc.com/sqrl/details.htm: After its single trailing (“=”) equals sign
         * is removed, the resulting 43-character string becomes the value for the sqrlkey parameter.
         *
         * Test for cases where the CHAR(44) pubkey includes a trailing space.
         */
        $nut = new \Varden\Hazelnut\Nut('sample');
        $key = "k";
        $nut
            -> createdAt(time())
            -> forIdentity("k ")
            -> withTIF('0')
            -> byIP('2001:db8::1');
        $result = $this->method->invoke($this->hazelnut, $nut, $key);
        $this->assertEquals(\Varden\Hazelnut\NUT_VALID, $result);
    }

    public function testNullNut() {
        $result = $this->method->invoke($this->hazelnut, null, null);
        $this->assertEquals(\Varden\Hazelnut\NUT_INVALID, $result);
    }

    public function testExpiredNut() {
        $nut = new \Varden\Hazelnut\Nut('sample');
        $nut
            -> createdAt(time() - 600)
            -> forIdentity($key = null)
            -> withTIF('0')
            -> byIP('2001:db8::1');
        $result = $this->method->invoke($this->hazelnut, $nut, $key);
        $this->assertEquals(\Varden\Hazelnut\NUT_EXPIRED, $result);
    }

    public function testMismatchingKey() {
        $nut = new \Varden\Hazelnut\Nut('sample');
        $nut
            -> createdAt(time())
            -> forIdentity(sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()))
            -> withTIF('0')
            -> byIP('2001:db8::1');
        $result = $this->method->invoke($this->hazelnut, $nut, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->assertEquals(\Varden\Hazelnut\NUT_MISMATCHING_ID, $result);
    }
}
