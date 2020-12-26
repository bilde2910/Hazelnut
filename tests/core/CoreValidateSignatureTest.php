<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::validateSignature
 * @uses \Varden\Hazelnut\Authenticator
 */
class CoreValidateSignatureTest extends \PHPUnit\Framework\TestCase {
    private $method;

    protected function setUp() :void {
        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'validateSignature');
        $this->method->setAccessible(true);
    }

    public function testProperlySignedMessage() {
        $message = 'This is a sample string to be signed';
        $kp = sodium_crypto_sign_keypair();
        $pubkey = sodium_crypto_sign_publickey($kp);
        $privkey = sodium_crypto_sign_secretkey($kp);
        $sig = sodium_crypto_sign_detached($message, $privkey);

        $result = $this->method->invoke(null, $message, $pubkey, $sig);
        $this->assertTrue($result);
    }

    public function testImproperlySignedMessage() {
        $message = 'This is a sample string to be signed';
        // Testing with different keys to ensure signature fails
        $privkey = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
        $pubkey = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());
        $sig = sodium_crypto_sign_detached($message, $privkey);

        $result = $this->method->invoke(null, $message, $pubkey, $sig);
        $this->assertFalse($result);
    }
}
