<?php
/**
 * @covers \Varden\Hazelnut\Authenticator::handleRequest
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 * @uses DummyKey
 * @uses DummyKeyStorage
 * @uses DummyNut
 * @uses DummyNutStorage
 */
class CoreHandleRequestTest extends \PHPUnit\Framework\TestCase {
    private $hazelnut;
    private $keyStore;
    private $nutStore;

    private $helperEncode;
    private $helperFormat;
    private $helperParse;
    private $dataNut;
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
            -> setSecure(true);

        $this->helperEncode = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encode');
        $this->helperEncode->setAccessible(true);
        $this->helperFormat = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'encodeOutput');
        $this->helperFormat->setAccessible(true);
        $this->helperParse = new ReflectionMethod('\Varden\Hazelnut\Authenticator', 'parseBaseData');
        $this->helperParse->setAccessible(true);
        $this->dataNut = $this->hazelnut->createAuthSession();

        $kp = sodium_crypto_sign_keypair();
        $this->dataPub = sodium_crypto_sign_publickey($kp);
        $this->dataPriv = sodium_crypto_sign_secretkey($kp);
    }

    public function testInvalidRequest() {
        $_GET = array(
            'nut' => $this->dataNut,
        );
        $_POST = array(
            'client' => array(),
            'server' => 'sqrl://example.com/sqrlauth.php?nut='.$this->dataNut
        );
        ob_start();
        $this->hazelnut->handleRequest();
        $result = $this->helperParse->invoke(null, ob_get_clean());

        $this->assertEquals('1', $result['ver'], 'Wrong version');
        $this->assertNull($this->nutStore->retrieve($result['nut']), 'Fail nut exists');
        $this->assertEquals('/sqrlauth.php?nut='.$result['nut'], $result['qry'], 'Qry doesn\'t match format');
        $this->assertEquals(\Varden\Hazelnut\TIF_COMMAND_FAILED | \Varden\Hazelnut\TIF_CLIENT_FAILURE, $result['tif'], 'TIF is incorrect');
        $this->assertFalse($this->hazelnut->isAuthenticated($this->dataNut), 'Client is authenticated');
    }

    public function testHandleQuery() {
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $_GET = array(
            'nut' => $this->dataNut,
        );
        $_POST = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$this->dataNut)
        );
        $_POST['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $this->dataPriv)
        );

        ob_start();
        $this->hazelnut->handleRequest();
        $result = $this->helperParse->invoke(null, ob_get_clean());

        $this->assertEquals('1', $result['ver'], 'Wrong version');
        $this->assertArrayNotHasKey('suk', $result, 'Response has SUK');
        $this->assertNotEquals($this->dataNut, $result['nut'], 'Nut is unchanged');
        $this->assertNull($this->nutStore->retrieve($this->dataNut), 'Old nut still exists');
        $this->assertNotNull($this->nutStore->retrieve($result['nut']), 'New nut doesn\'t exist');
        $this->assertEquals('/sqrlauth.php?nut='.$result['nut'], $result['qry'], 'Qry doesn\'t match format');
        $this->assertEquals(\Varden\Hazelnut\TIF_IP_MATCH, $result['tif'], 'TIF is incorrect');
        $this->assertFalse($this->hazelnut->isAuthenticated($this->dataNut), 'Client is authenticated');
    }

    public function testHandleIdent() {
        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'ident',
            'suk' => $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair())),
            'vuk' => $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()))
        );
        $_GET = array(
            'nut' => $this->dataNut,
        );
        $_POST = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$this->dataNut)
        );
        $_POST['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $this->dataPriv)
        );

        ob_start();
        $this->hazelnut->handleRequest();
        $result = $this->helperParse->invoke(null, ob_get_clean());

        $this->assertEquals('1', $result['ver'], 'Wrong version');
        $this->assertArrayNotHasKey('suk', $result, 'Response has SUK');
        $this->assertNotEquals($this->dataNut, $result['nut'], 'Nut is unchanged');
        $this->assertNull($this->nutStore->retrieve($this->dataNut), 'Old nut still exists');
        $this->assertNotNull($this->nutStore->retrieve($result['nut']), 'New nut doesn\'t exist');
        $this->assertEquals('/sqrlauth.php?nut='.$result['nut'], $result['qry'], 'Qry doesn\'t match format');
        $this->assertEquals(\Varden\Hazelnut\TIF_IP_MATCH | \Varden\Hazelnut\TIF_CID_MATCH, $result['tif'], 'TIF is incorrect');
        $this->assertTrue($this->hazelnut->isAuthenticated($this->dataNut), 'Client isn\'t authenticated');
    }

    public function testHandleLock() {
        $suk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $vuk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->keyStore->create($this->helperEncode->invoke(null, $this->dataPub), $suk, $vuk);

        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'lock',
            'suk' => $suk,
            'vuk' => $vuk
        );
        $_GET = array(
            'nut' => $this->dataNut,
        );
        $_POST = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$this->dataNut)
        );
        $_POST['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $this->dataPriv)
        );

        ob_start();
        $this->hazelnut->handleRequest();
        $result = $this->helperParse->invoke(null, ob_get_clean());

        $this->assertEquals('1', $result['ver'], 'Wrong version');
        $this->assertNotEquals($this->dataNut, $result['nut'], 'Nut is unchanged');
        $this->assertNull($this->nutStore->retrieve($this->dataNut), 'Old nut still exists');
        $this->assertNotNull($this->nutStore->retrieve($result['nut']), 'New nut doesn\'t exist');
        $this->assertNotEquals($this->dataNut, $this->nutStore->forceGetOriginal($result['nut']));
        $this->assertEquals('/sqrlauth.php?nut='.$result['nut'], $result['qry'], 'Qry doesn\'t match format');
        $this->assertEquals(
            \Varden\Hazelnut\TIF_IP_MATCH |
            \Varden\Hazelnut\TIF_CID_MATCH |
            \Varden\Hazelnut\TIF_ID_DISABLED,
            $result['tif'], 'TIF is incorrect'
        );
        $this->assertArrayNotHasKey('suk', $result, 'Response has SUK');
        $this->assertFalse($this->hazelnut->isAuthenticated($this->dataNut), 'Client isn\'t authenticated');
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED, $this->keyStore->getState($client['idk']), 'Key not locked');
    }

    public function testFailedChaining() {
        $suk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $vuk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));

        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'lock~ident',
            'suk' => $suk,
            'vuk' => $vuk
        );
        $_GET = array(
            'nut' => $this->dataNut,
        );
        $_POST = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$this->dataNut)
        );
        $_POST['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $this->dataPriv)
        );

        ob_start();
        $this->hazelnut->handleRequest();
        $result = $this->helperParse->invoke(null, ob_get_clean());

        $this->assertEquals(
            \Varden\Hazelnut\TIF_IP_MATCH |
            \Varden\Hazelnut\TIF_COMMAND_FAILED |
            \Varden\Hazelnut\TIF_CLIENT_FAILURE,
            $result['tif'], 'TIF is incorrect'
        );
        $this->assertFalse($this->hazelnut->isAuthenticated($this->dataNut), 'Client is authenticated');
    }

    public function testSuccessfulChaining() {
        $suk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $vuk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));

        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'ident~lock',
            'suk' => $suk,
            'vuk' => $vuk
        );
        $_GET = array(
            'nut' => $this->dataNut,
        );
        $_POST = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$this->dataNut)
        );
        $_POST['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $this->dataPriv)
        );

        ob_start();
        $this->hazelnut->handleRequest();
        $result = $this->helperParse->invoke(null, ob_get_clean());

        $this->assertEquals(
            \Varden\Hazelnut\TIF_IP_MATCH |
            \Varden\Hazelnut\TIF_CID_MATCH |
            \Varden\Hazelnut\TIF_ID_DISABLED,
            $result['tif'], 'TIF is incorrect'
        );
        $this->assertArrayNotHasKey('suk', $result, 'Response has SUK');
        $this->assertFalse($this->hazelnut->isAuthenticated($this->dataNut), 'Client is authenticated');
        $this->assertEquals(\Varden\Hazelnut\KeyStorage::KEY_STATE_DISABLED, $this->keyStore->getState($client['idk']), 'Key state not locked');
    }

    public function testHandleDisabledQuery() {
        $suk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $vuk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->keyStore->create($this->helperEncode->invoke(null, $this->dataPub), $suk, $vuk);
        $this->keyStore->disable($this->helperEncode->invoke(null, $this->dataPub));

        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query'
        );
        $_GET = array(
            'nut' => $this->dataNut,
        );
        $_POST = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$this->dataNut)
        );
        $_POST['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $this->dataPriv)
        );

        ob_start();
        $this->hazelnut->handleRequest();
        $result = $this->helperParse->invoke(null, ob_get_clean());

        $this->assertEquals('1', $result['ver'], 'Wrong version');
        $this->assertArrayHasKey('suk', $result, 'Response doesn\'t have SUK');
        $this->assertEquals($suk, $result['suk'], 'SUK doesn\'t match');
        $this->assertNotEquals($this->dataNut, $result['nut'], 'Nut is unchanged');
        $this->assertNull($this->nutStore->retrieve($this->dataNut), 'Old nut still exists');
        $this->assertNotNull($this->nutStore->retrieve($result['nut']), 'New nut doesn\'t exist');
        $this->assertEquals('/sqrlauth.php?nut='.$result['nut'], $result['qry'], 'Qry doesn\'t match format');
        $this->assertEquals(
            \Varden\Hazelnut\TIF_IP_MATCH |
            \Varden\Hazelnut\TIF_CID_MATCH |
            \Varden\Hazelnut\TIF_ID_DISABLED,
            $result['tif'], 'TIF is incorrect'
        );
        $this->assertFalse($this->hazelnut->isAuthenticated($this->dataNut), 'Client is authenticated');
    }

    public function testHandleDisabledQueryLock() {
        $suk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $vuk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->keyStore->create($this->helperEncode->invoke(null, $this->dataPub), $suk, $vuk);
        $this->keyStore->disable($this->helperEncode->invoke(null, $this->dataPub));

        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'cmd' => 'query~lock'
        );
        $_GET = array(
            'nut' => $this->dataNut,
        );
        $_POST = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$this->dataNut)
        );
        $_POST['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $this->dataPriv)
        );

        ob_start();
        $this->hazelnut->handleRequest();
        $result = $this->helperParse->invoke(null, ob_get_clean());

        $this->assertEquals('1', $result['ver'], 'Wrong version');
        $this->assertArrayNotHasKey('suk', $result, 'Response has SUK');
        $this->assertNotEquals($this->dataNut, $result['nut'], 'Nut is unchanged');
        $this->assertNull($this->nutStore->retrieve($this->dataNut), 'Old nut still exists');
        $this->assertNotNull($this->nutStore->retrieve($result['nut']), 'New nut doesn\'t exist');
        $this->assertEquals('/sqrlauth.php?nut='.$result['nut'], $result['qry'], 'Qry doesn\'t match format');
        $this->assertEquals(
            \Varden\Hazelnut\TIF_IP_MATCH |
            \Varden\Hazelnut\TIF_CID_MATCH |
            \Varden\Hazelnut\TIF_ID_DISABLED,
            $result['tif'], 'TIF is incorrect'
        );
        $this->assertFalse($this->hazelnut->isAuthenticated($this->dataNut), 'Client is authenticated');
    }

    public function testHandlePidkExistsQuery() {
        $pidk = sodium_crypto_sign_keypair();
        $pidkPub = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey($pidk));
        $pidkPriv = sodium_crypto_sign_secretkey($pidk);
        $suk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $vuk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->keyStore->create($pidkPub, $suk, $vuk);

        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'pidk' => $pidkPub,
            'cmd' => 'query'
        );
        $_GET = array(
            'nut' => $this->dataNut,
        );
        $_POST = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$this->dataNut)
        );
        $_POST['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $this->dataPriv)
        );
        $_POST['pids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $pidkPriv)
        );

        ob_start();
        $this->hazelnut->handleRequest();
        $result = $this->helperParse->invoke(null, ob_get_clean());

        $this->assertEquals('1', $result['ver'], 'Wrong version');
        $this->assertNotEquals($this->dataNut, $result['nut'], 'Nut is unchanged');
        $this->assertNull($this->nutStore->retrieve($this->dataNut), 'Old nut still exists');
        $this->assertNotNull($this->nutStore->retrieve($result['nut']), 'New nut doesn\'t exist');
        $this->assertEquals('/sqrlauth.php?nut='.$result['nut'], $result['qry'], 'Qry doesn\'t match format');
        $this->assertEquals(
            \Varden\Hazelnut\TIF_IP_MATCH |
            \Varden\Hazelnut\TIF_PID_MATCH,
            $result['tif'], 'TIF is incorrect'
        );
        $this->assertFalse($this->hazelnut->isAuthenticated($this->dataNut), 'Client is authenticated');
        $this->assertArrayHasKey('suk', $result, 'Response doesn\'t have SUK');
        $this->assertEquals($suk, $result['suk'], 'SUK doesn\'t match');
    }

    public function testHandlePidkExistsQueryIdent() {
        $pidk = sodium_crypto_sign_keypair();
        $pidkPub = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey($pidk));
        $pidkPriv = sodium_crypto_sign_secretkey($pidk);
        $suk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $vuk = $this->helperEncode->invoke(null, sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        $this->keyStore->create($pidkPub, $suk, $vuk);

        $client = array(
            'ver' => '1',
            'idk' => $this->helperEncode->invoke(null, $this->dataPub),
            'pidk' => $pidkPub,
            'cmd' => 'query~ident',
            'suk' => $suk,
            'vuk' => $vuk
        );
        $_GET = array(
            'nut' => $this->dataNut,
        );
        $_POST = array(
            'client' => $this->helperFormat->invoke(null, $client),
            'server' => $this->helperEncode->invoke(null, 'sqrl://example.com/sqrlauth.php?nut='.$this->dataNut)
        );
        $_POST['ids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $this->dataPriv)
        );
        $_POST['pids'] = $this->helperEncode->invoke(null,
            sodium_crypto_sign_detached($_POST['client'].$_POST['server'], $pidkPriv)
        );

        ob_start();
        $this->hazelnut->handleRequest();
        $result = $this->helperParse->invoke(null, ob_get_clean());

        $this->assertEquals('1', $result['ver'], 'Wrong version');
        $this->assertNotEquals($this->dataNut, $result['nut'], 'Nut is unchanged');
        $this->assertNull($this->nutStore->retrieve($this->dataNut), 'Old nut still exists');
        $this->assertNotNull($this->nutStore->retrieve($result['nut']), 'New nut doesn\'t exist');
        $this->assertEquals('/sqrlauth.php?nut='.$result['nut'], $result['qry'], 'Qry doesn\'t match format');
        $this->assertEquals(
            \Varden\Hazelnut\TIF_IP_MATCH |
            \Varden\Hazelnut\TIF_CID_MATCH |
            \Varden\Hazelnut\TIF_PID_MATCH,
            $result['tif'], 'TIF is incorrect'
        );
        $this->assertTrue($this->hazelnut->isAuthenticated($this->dataNut), 'Client isn\'t authenticated');
        $this->assertArrayNotHasKey('suk', $result, 'Response has SUK');
        $this->assertEquals(
            \Varden\Hazelnut\KeyStorage::KEY_STATE_UNKNOWN,
            $this->keyStore->getState($pidkPub),
            'Old account still exists'
        );
    }
}
