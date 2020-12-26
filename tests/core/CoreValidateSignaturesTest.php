<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::validateSignatures
 * @uses \Varden\Hazelnut\Authenticator
 * @uses DummyKey
 * @uses DummyKeyStorage
 */
class CoreValidateSignaturesTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $keyStore;
    private $nutStore;
    private $method;

    private $helperEncode;
    private $helperFormat;

    protected function setUp() :void {
        $this->keyStore = new DummyKeyStorage();
        $this->nutStore = new DummyNutStorage();
        $this->hazelnut = new \Varden\Hazelnut\Authenticator($this->keyStore, $this->nutStore);
        $this->hazelnut
            -> setSite('example.com')
            -> setAuthPath('/sqrlauth.php')
            -> setRemoteIP('2001:db8::1')
            -> setExpiryMinutes(10)
            -> setSecure(true)
            -> setFriendlyName('Unit Test');

        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'validateSignatures');
        $this->method->setAccessible(true);

        $this->helperEncode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $this->helperEncode->setAccessible(true);
        $this->helperFormat = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encodeOutput');
        $this->helperFormat->setAccessible(true);
    }

    public function testValidIdk() {
        $idk = sodium_crypto_sign_keypair();
        $idkPub = sodium_crypto_sign_publickey($idk);
        $idkPriv = sodium_crypto_sign_secretkey($idk);

        $client = array(
            'idk' => $this->helperEncode->invoke(null, $idkPub)
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperFormat->invoke(null, array())
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $idkPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $post, $client);
        $this->assertTrue($result);
    }

    public function testBrokenIdk() {
        $idkPub = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());
        $idkPriv = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());

        $client = array(
            'idk' => $this->helperEncode->invoke(null, $idkPub)
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperFormat->invoke(null, array())
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $idkPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $post, $client);
        $this->assertFalse($result);
    }

    public function testValidIdkAndValidPidk() {
        $idk = sodium_crypto_sign_keypair();
        $idkPub = sodium_crypto_sign_publickey($idk);
        $idkPriv = sodium_crypto_sign_secretkey($idk);
        $pidk = sodium_crypto_sign_keypair();
        $pidkPub = sodium_crypto_sign_publickey($pidk);
        $pidkPriv = sodium_crypto_sign_secretkey($pidk);

        $client = array(
            'idk' => $this->helperEncode->invoke(null, $idkPub),
            'pidk' => $this->helperEncode->invoke(null, $pidkPub)
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperFormat->invoke(null, array())
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $idkPriv)
        );
        $post['pids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $pidkPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $post, $client);
        $this->assertTrue($result);
    }

    public function testValidIdkAndBrokenPidk() {
        $idk = sodium_crypto_sign_keypair();
        $idkPub = sodium_crypto_sign_publickey($idk);
        $idkPriv = sodium_crypto_sign_secretkey($idk);
        $pidkPub = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());
        $pidkPriv = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());

        $client = array(
            'idk' => $this->helperEncode->invoke(null, $idkPub),
            'pidk' => $this->helperEncode->invoke(null, $pidkPub)
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperFormat->invoke(null, array())
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $idkPriv)
        );
        $post['pids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $pidkPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $post, $client);
        $this->assertFalse($result);
    }

    public function testFlippedIdkAndPidk() {
        $idk = sodium_crypto_sign_keypair();
        $idkPub = sodium_crypto_sign_publickey($idk);
        $idkPriv = sodium_crypto_sign_secretkey($idk);
        $pidk = sodium_crypto_sign_keypair();
        $pidkPub = sodium_crypto_sign_publickey($pidk);
        $pidkPriv = sodium_crypto_sign_secretkey($pidk);

        $client = array(
            'idk' => $this->helperEncode->invoke(null, $pidkPub),
            'pidk' => $this->helperEncode->invoke(null, $idkPub)
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperFormat->invoke(null, array())
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $idkPriv)
        );
        $post['pids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $pidkPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $post, $client);
        $this->assertFalse($result);
    }

    public function testValidIdkAndValidUrsWithVuk() {
        $idk = sodium_crypto_sign_keypair();
        $idkPub = sodium_crypto_sign_publickey($idk);
        $idkPriv = sodium_crypto_sign_secretkey($idk);
        $vuk = sodium_crypto_sign_keypair();
        $vukPub = sodium_crypto_sign_publickey($vuk);
        $vukPriv = sodium_crypto_sign_secretkey($vuk);

        $client = array(
            'idk' => $this->helperEncode->invoke(null, $idkPub),
            'vuk' => $this->helperEncode->invoke(null, $vukPub)
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperFormat->invoke(null, array())
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $idkPriv)
        );
        $post['urs'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $vukPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $post, $client);
        $this->assertTrue($result);
    }

    public function testValidIdkAndBrokenUrsWithVuk() {
        $idk = sodium_crypto_sign_keypair();
        $idkPub = sodium_crypto_sign_publickey($idk);
        $idkPriv = sodium_crypto_sign_secretkey($idk);
        $vukPub = sodium_crypto_sign_publickey(sodium_crypto_sign_keypair());
        $vukPriv = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());

        $client = array(
            'idk' => $this->helperEncode->invoke(null, $idkPub),
            'vuk' => $this->helperEncode->invoke(null, $vukPub)
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperFormat->invoke(null, array())
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $idkPriv)
        );
        $post['urs'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $vukPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $post, $client);
        $this->assertFalse($result);
    }

    public function testValidIdkAndValidUrsWithPidk() {
        $idk = sodium_crypto_sign_keypair();
        $idkPub = sodium_crypto_sign_publickey($idk);
        $idkPriv = sodium_crypto_sign_secretkey($idk);
        $pidk = sodium_crypto_sign_keypair();
        $pidkPub = sodium_crypto_sign_publickey($pidk);
        $pidkPriv = sodium_crypto_sign_secretkey($pidk);
        $vuk = sodium_crypto_sign_keypair();
        $vukPub = sodium_crypto_sign_publickey($vuk);
        $vukPriv = sodium_crypto_sign_secretkey($vuk);

        $client = array(
            'idk' => $this->helperEncode->invoke(null, $idkPub),
            'pidk' => $this->helperEncode->invoke(null, $pidkPub)
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperFormat->invoke(null, array())
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $idkPriv)
        );
        $post['urs'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $vukPriv)
        );

        $this->keyStore->create($client['pidk'], 'suk', $this->helperEncode->invoke(null, $vukPub));

        $result = $this->method->invoke($this->hazelnut, $post, $client);
        $this->assertTrue($result);
    }
}
