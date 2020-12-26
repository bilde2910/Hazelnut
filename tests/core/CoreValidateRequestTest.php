<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::validateRequest
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 * @uses DummyNut
 * @uses DummyNutStorage
 */
class CoreValidateRequestTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $keyStore;
    private $nutStore;
    private $method;

    private $helperEncode;
    private $helperFormat;
    private $dataPub;
    private $dataPriv;

    protected function setUp() :void {
        $this->keyStore = new DummyKeyStorage();
        $this->nutStore = new DummyNutStorage();
        $this->hazelnut = new \Varden\Hazelnut\Authenticator($this->keyStore, $this->nutStore);
        $this->hazelnut
            -> setSite('example.com')
            -> setAuthPath('/sqrlauth.php')
            -> setRemoteIP('2001:db8::1')
            -> setExpiryMinutes(10)
            -> setSecure(true);

        $this->method = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'validateRequest');
        $this->method->setAccessible(true);

        $this->helperEncode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $this->helperEncode->setAccessible(true);
        $this->helperFormat = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encodeOutput');
        $this->helperFormat->setAccessible(true);
        $idk = sodium_crypto_sign_keypair();
        $this->dataPub = sodium_crypto_sign_publickey($idk);
        $this->dataPriv = sodium_crypto_sign_secretkey($idk);
    }

    public function testValidRequest() {
        $nut = $this->hazelnut->createAuthSession();
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $get = array(
            'nut' => $nut
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$nut)
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $this->dataPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $get, $post);
        $this->assertEquals(
            \Varden\Hazelnut\TIF_IP_MATCH,
            $result
        );
    }

    public function testUnsupportedVersion() {
        $nut = $this->hazelnut->createAuthSession();
        $client = array(
            'ver' => '10',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $get = array(
            'nut' => $nut
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$nut)
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $this->dataPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $get, $post);
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_NOT_SUPPORTED,
            $result
        );
    }

    public function testMissingClientFields() {
        $nut = $this->hazelnut->createAuthSession();
        $client = array(
            'idk' => $this->helperEncode->invoke(null, $this->dataPub)
        );
        $get = array(
            'nut' => $nut
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$nut)
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $this->dataPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $get, $post);
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result
        );
    }

    public function testMissingPostFields() {
        $nut = $this->hazelnut->createAuthSession();
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $get = array(
            'nut' => $nut
        );

        $result = $this->method->invoke($this->hazelnut, $get, array());
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result
        );
    }

    public function testMissingGetFields() {
        $nut = $this->hazelnut->createAuthSession();
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$nut)
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $this->dataPriv)
        );

        $result = $this->method->invoke($this->hazelnut, array(), $post);
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result
        );
    }

    public function testInvalidServerData() {
        $nut = $this->hazelnut->createAuthSession();
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $get = array(
            'nut' => $nut
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/wrong.php?nut='.$nut)
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $this->dataPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $get, $post);
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result
        );
    }

    public function testExpiredNut() {
        $nut = $this->hazelnut->createAuthSession();
        $this->nutStore->forceSetNutCreated($nut, time() - 1200);
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $get = array(
            'nut' => $nut
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$nut)
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $this->dataPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $get, $post);
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_TRANSIENT_ERROR,
            $result
        );
    }

    public function testMismatchingNutKey() {
        $nut = $this->hazelnut->createAuthSession();
        $this->nutStore->forceSetNutPubkey($nut, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $get = array(
            'nut' => $nut
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$nut)
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $this->dataPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $get, $post);
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE |
            \Varden\Hazelnut\TIF_MISMATCHING_NUT_ID,
            $result
        );
    }

    public function testNullNut() {
        $nut = 'sample';
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $get = array(
            'nut' => $nut
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$nut)
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $this->dataPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $get, $post);
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result
        );
    }

    public function testInvalidSignature() {
        $nut = $this->hazelnut->createAuthSession();
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair())),
            'cmd' => 'query'
        );
        $get = array(
            'nut' => $nut
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$nut)
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $this->dataPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $get, $post);
        $this->assertEquals(
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result
        );
    }

    public function testMismatchingNutIP() {
        $nut = $this->hazelnut->createAuthSession();
        $this->nutStore->forceSetNutIP($nut, '2001:db8::2');
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $get = array(
            'nut' => $nut
        );
        $post = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$nut)
        );
        $post['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($post['client'].$post['server'], $this->dataPriv)
        );

        $result = $this->method->invoke($this->hazelnut, $get, $post);
        $this->assertEquals(
            0,
            $result
        );
    }
}
