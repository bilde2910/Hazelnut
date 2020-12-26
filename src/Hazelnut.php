<?php declare(strict_types=1);

/*
Copyright 2020 Marius Lindvall

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

namespace Varden\Hazelnut;

const TIF_CID_MATCH             = 0x1;
const TIF_PID_MATCH             = 0x2;
const TIF_IP_MATCH              = 0x4;
const TIF_ID_DISABLED           = 0x8;
const TIF_NOT_SUPPORTED         = 0x10;
const TIF_TRANSIENT_ERROR       = 0x20;
const TIF_COMMAND_FAILED        = 0x40;
const TIF_CLIENT_FAILURE        = 0x80;
const TIF_MISMATCHING_NUT_ID    = 0x100;

const NUT_VALID             = 0;
const NUT_INVALID           = 1;
const NUT_EXPIRED           = 2;
const NUT_MISMATCHING_ID    = 3;

class Authenticator {
    private $uriConfig;
    private $storage;
    private $nuts;

    private $site;
    private $authPath;
    private $secure;
    private $params;
    private $nutExpiry;
    private $remoteIP;

    function __construct(KeyStorage $storage, NutStorage $nuts) {
        $this->storage = $storage;
        $this->nuts = $nuts;

        global $_SERVER;
        $this->site = empty($_SERVER['HTTP_HOST']) ? '' : $_SERVER['HTTP_HOST'];
        $this->authPath = '/';
        $this->params = array();
        $this->nutExpiry = 5;
        $this->remoteIP = empty($_SERVER['REMOTE_ADDR']) ? '' : $_SERVER['REMOTE_ADDR'];
        $this->secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    }

    /* =========================== CONFIGURATION =========================== */

    public function setSite(string $site) :Authenticator {
        $this->site = $site;
        if (strpos($site, '/') !== false) {
            $this->params['x'] = strlen($site) - strpos($site, '/');
        } else {
            unset($this->params['x']);
        }
        return $this;
    }

    public function setSecure(bool $secure) :Authenticator {
        $this->secure = $secure;
        return $this;
    }

    public function setAuthPath(string $path) :Authenticator {
        $this->authPath = $path;
        return $this;
    }

    public function setFriendlyName(string $name) :Authenticator {
        $this->params['sfn'] = self::encode($name);
        return $this;
    }

    public function setExpiryMinutes(int $minutes) :Authenticator {
        $this->nutExpiry = $minutes;
        return $this;
    }

    public function setRemoteIP(string $ip) :Authenticator {
        $this->remoteIP = $ip;
        return $this;
    }

    /* ========================= PUBLIC FUNCTIONS ========================= */

    public function handleRequest() :void {
        global $_GET;
        global $_POST;
        $tif = $this->validateRequest($_GET, $_POST);

        $response = array(
            'ver' => '1',
            'nut' => 'fail'
        );

        if (!($tif & TIF_COMMAND_FAILED)) {
            $client = self::parseBaseData($_POST['client']);
            $nut = $_GET['nut'];
            $commands = explode('~', $client['cmd']);
            $options = isset($client['opt']) ? explode('~', $client['opt']) : array();
            $locked = false;

            foreach ($commands as $cmd) {
                if (!!($tif & TIF_COMMAND_FAILED)) break;
                switch ($cmd) {
                    case 'query':
                        $tif |= $this->handleQuery($client);
                        break;
                    case 'ident':
                        $tif |= $this->handleIdent($client, $nut);
                        break;
                    case 'lock':
                        $tif |= $this->handleLock($client, $nut);
                        $locked = true;
                        break;
                }
            }

            if ($locked) $nut = null;
            $response['nut'] = $this->generateNut($tif, $client['idk'], $nut);
            if (!!($tif & TIF_ID_DISABLED) && !in_array('lock', $commands)) {
                $response['suk'] = $this->storage->getSUK($client['idk']);
            } else if (!!($tif & TIF_PID_MATCH) && !in_array('ident', $commands)) {
                $response['suk'] = $this->storage->getSUK($client['pidk']);
            }
        }

        $response['qry'] = $this->generateQry($response['nut']);
        $response['tif'] = $tif;

        echo self::encodeOutput($response);
    }

    public function createAuthSession() :string {
        return $this->generateNut();
    }

    public function isAuthenticated($session) :bool {
        return $this->nuts->isVerified($session);
    }

    public function getSqrlUri(string $session) :string {
        $this->params['nut'] = $session;
        krsort($this->params);
        return ($this->secure ? 'sqrl' : 'qrl') . '://' . $this->site .
            $this->authPath . '?' . http_build_query($this->params);
    }

    /* ========================= PRIVATE FUNCTIONS ========================= */

    private function generateNut(int $tif = 0, ?string $key = null, ?string $orig = null) :string {
        $nut = self::encode(openssl_random_pseudo_bytes(32));
        if ($orig == null) {
            $this->nuts->deposit($nut, self::toFullIPv6Address($this->remoteIP), $tif, $key);
        } else {
            $this->nuts->replace($orig, $nut, self::toFullIPv6Address($this->remoteIP), $tif, $key);
        }
        return $nut;
    }

    private function generateQry(string $nut) :string {
        $uri = parse_url($this->getSqrlUri($nut));
        return $uri['path'] . '?' . (isset($uri['query']) ? $uri['query'] : '');
    }

    private function handleQuery(array $client) :int {
        $state = $this->storage->getState($client['idk']);
        if ($state == KeyStorage::KEY_STATE_ACTIVE) {
            return TIF_CID_MATCH;
        } else if ($state == KeyStorage::KEY_STATE_DISABLED) {
            return TIF_CID_MATCH | TIF_ID_DISABLED;
        } else if (isset($client['pidk']) && $this->storage->getState($client['pidk']) == KeyStorage::KEY_STATE_ACTIVE) {
            return TIF_PID_MATCH;
        } else {
            return 0;
        }
    }

    private function handleIdent(array $client, string $nut) :int {
        $state = $this->storage->getState($client['idk']);
        switch ($state) {
            case KeyStorage::KEY_STATE_ACTIVE:
                $this->nuts->markVerified($nut);
                return TIF_CID_MATCH;
            case KeyStorage::KEY_STATE_UNKNOWN:
                if (!self::ensureValuesSet($client, 'suk', 'vuk')) return self::fail();
                if (isset($client['pidk']) && $this->storage->getState($client['pidk']) != KeyStorage::KEY_STATE_UNKNOWN) {
                    $this->storage->migrate($client['pidk'], $client['idk'], $client['suk'], $client['vuk']);
                    $this->nuts->markVerified($nut);
                    return TIF_CID_MATCH | TIF_PID_MATCH;
                } else {
                    $this->storage->create($client['idk'], $client['suk'], $client['vuk']);
                    $this->nuts->markVerified($nut);
                    return TIF_CID_MATCH;
                }
            case KeyStorage::KEY_STATE_DISABLED:
                if (!self::ensureValuesSet($client, 'suk', 'vuk')) return self::fail();
                if ($this->storage->getVUK($client['idk']) != $client['vuk']) return self::fail();
                $this->storage->enable($client['idk']);
                $this->nuts->markVerified($nut);
                return TIF_CID_MATCH;
            default:
                // Should never happen with properly implemented nut storage
                throw new \Exception('Invalid key state returned by nut storage');
        }
    }

    private function handleLock(array $client, string $nut) :int {
        $state = $this->storage->getState($client['idk']);
        if ($state == KeyStorage::KEY_STATE_UNKNOWN) return self::fail();
        $this->storage->disable($client['idk']);
        $this->nuts->destroy($nut);
        return TIF_CID_MATCH | TIF_ID_DISABLED;
    }

    private function validateRequest(array $get, array $post) :int {
        $tif = 0x0;

        if (!self::ensureValuesSet($post, 'client', 'server', 'ids') || !self::ensureValuesSet($get, 'nut')) {
            $tif = self::fail();
        } else {
            $client = self::parseBaseData($post['client']);
            $server = self::parseBaseData($post['server']);
            $nut = $this->nuts->retrieve($get['nut']);
            $nutStatus = $this->validateNut($nut, isset($client['idk']) ? $client['idk'] : null);
            if (!self::ensureValuesSet($client, 'ver', 'idk', 'cmd')) {
                $tif = self::fail();
            } else if ($client['ver'] !== '1') {
                $tif = self::fail(TIF_NOT_SUPPORTED);
            } else if ($nutStatus == NUT_INVALID) {
                $tif = self::fail();
            } else if (!$this->validateServerData($server, $nut)) {
                $tif = self::fail();
            } else if ($nutStatus == NUT_EXPIRED) {
                $tif = self::fail(TIF_TRANSIENT_ERROR);
                // set IDK
            } else if ($nutStatus == NUT_MISMATCHING_ID) {
                $tif = self::fail(TIF_CLIENT_FAILURE | TIF_MISMATCHING_NUT_ID);
            } else if (!$this->validateSignatures($post, $client)) {
                $tif = self::fail();
            } else {
                if (self::toFullIPv6Address($nut->getIP()) == self::toFullIPv6Address($this->remoteIP)) {
                    $tif |= TIF_IP_MATCH;
                }
            }
        }

        return $tif;
    }

    private function validateNut(?Nut $nut, ?string $key) :int {
        if ($nut == null) return NUT_INVALID;
        if ($nut->getCreatedTime() < strtotime('-'.$this->nutExpiry.' minutes')) return NUT_EXPIRED;
        if ($key != null && $nut->getIdentity() != null && $key != $nut->getIdentity()) return NUT_MISMATCHING_ID;
        return NUT_VALID;
    }

    private function validateServerData($server, Nut $nut) :bool {
        if (is_string($server) && $nut != null) {
            return $server == $this->getSqrlUri($nut->getNut());
        }
        else if (!self::ensureValuesSet($server, 'ver', 'nut', 'tif', 'qry')) {
            return false;
        }
        else if ($nut == null || $server['nut'] != $nut->getNut()) {
            return false;
        }
        else if ($server['tif'] != $nut->getTIF()) {
            return false;
        }
        else if ($server['qry'] != $this->generateQry($nut->getNut())) {
            return false;
        }
        return true;
    }

    private function validateSignatures(array $post, array $client) :bool {
        $body = $post['client'].$post['server'];
        if (!self::validateSignature($body, self::decode($client['idk']), self::decode($post['ids']))) {
            return false;
        }
        if (isset($post['urs'])) {
            $urs = self::decode($post['urs']);
            if (!isset($client['vuk']) && isset($client['pidk'])) {
                if (!self::validateSignature($body, self::decode($this->storage->getVUK($client['pidk'])), $urs)) {
                    return false;
                }
            } else if (isset($client['vuk']) && !isset($client['pidk'])) {
                if (!self::validateSignature($body, self::decode($client['vuk']), $urs)) {
                    return false;
                }
            }
        }
        if (isset($post['pids']) && isset($client['pidk'])) {
            if (!self::validateSignature($body, self::decode($client['pidk']), self::decode($post['pids']))) {
                return false;
            }
        }
        return true;
    }

    private static function validateSignature(string $data, string $key, string $sig) :bool {
        return sodium_crypto_sign_verify_detached($sig, $data, $key);
    }

    private static function ensureValuesSet(array $array, ...$keys) :bool {
        foreach ($keys as $key) if (!isset($array[$key]) || $array[$key] === '') return false;
        return true;
    }

    private static function encode(string $binary) :string {
        return str_replace(array('+', '/'), array('-', '_'), rtrim(base64_encode($binary), '='));
    }

    private static function decode(string $binary) :string {
        return base64_decode(str_replace(array('-', '_'), array('+', '/'), $binary));
    }

    private static function encodeOutput(array $data) :string {
        $response = array();
        foreach ($data as $key => $value) $response[] = $key . '=' . $value;
        return self::encode(implode("\r\n", $response));
    }

    private static function toFullIPv6Address(string $ip) :string {
        if (preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $ip)) {
            $result = str_pad('ffff'.dechex(ip2long($ip)), 32, '0', STR_PAD_LEFT);
        } else {
            $result = '';
            if (substr($ip, 0, 1) == ':') $ip = '0' . $ip;
            if (substr($ip, -1) == ':') $ip .= '0';
            $parts = explode(':', $ip);
            foreach ($parts as $part) {
                if (strlen($part) == 0) {
                    $result .= str_pad('', 4 * (8 - sizeof($parts) + 1), '0');
                } else {
                    $result .= str_pad($part, 4, '0', STR_PAD_LEFT);
                }
            }
        }
        return trim(chunk_split(strtolower($result), 4, ':'), ':');
    }

    private static function fail(int $code = TIF_CLIENT_FAILURE) :int {
        return TIF_COMMAND_FAILED | $code;
    }

    private static function parseBaseData(string $binary) {
        $str = self::decode($binary);
        if (substr($str, 0, 7) == 'sqrl://' || substr($str, 0, 6) == 'qrl://') return $str;
        $fields = explode("\r\n", $str);
        $data = array();
        foreach ($fields as $field) {
            $separator = strpos($field, '=');
            if ($separator === false) continue;
            $data[substr($field, 0, $separator)] = substr($field, $separator + 1);
        }
        return $data;
    }
}

class Nut {
    private $nut;
    private $created = null;
    private $identity = null;
    private $tif = 0;
    private $ip = null;
    private $verified = false;

    function __construct(string $nut) {
        $this->nut = $nut;
    }

    public function createdAt(int $unixtime) :Nut {
        $this->created = $unixtime;
        return $this;
    }

    public function forIdentity(?string $identity) :Nut {
        $this->identity = $identity;
        return $this;
    }

    public function withTIF(int $tif) :Nut {
        $this->tif = $tif;
        return $this;
    }

    public function byIP(string $ipv6addr) :Nut {
        $this->ip = $ipv6addr;
        return $this;
    }

    public function getNut() :string {
        return $this->nut;
    }

    public function getCreatedTime() :int {
        return $this->created;
    }

    public function getIdentity() :?string {
        return $this->identity;
    }

    public function getTIF() :int {
        return $this->tif;
    }

    public function getIP() :string {
        return $this->ip;
    }
}

interface KeyStorage {
    const KEY_STATE_ACTIVE = 0;
    const KEY_STATE_DISABLED = 1;
    const KEY_STATE_UNKNOWN = 2;

    public function getState(string $identity) :int;
    public function disable(string $identity) :void;
    public function enable(string $identity) :void;
    public function getVUK(string $identity) :?string;
    public function getSUK(string $identity) :?string;
    public function migrate(string $oldId, string $newId, string $suk, string $vuk) :void;
    public function create(string $identity, string $suk, string $vuk) :void;
}

interface NutStorage {
    public function retrieve(string $nut) :?Nut;
    public function deposit(string $nut, string $ip, int $tif, ?string $key) :void;
    public function replace(string $oldNut, string $newNut, string $ip, int $tif, ?string $key) :void;
    public function destroy(string $nut) :void;
    public function markVerified(string $nut) :void;
    public function isVerified(string $origNut) :bool;
}
