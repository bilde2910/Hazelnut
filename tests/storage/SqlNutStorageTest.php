<?php
/**
 * @covers \Varden\Hazelnut\SqlNutStorage
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 * @uses DummyNut
 * @uses DummyNutStorage
 */
class SqlNutStorageTest extends NutStorageTestingTemplate {
    private $storage;
    private $pdo;

    private const SQL_DSN      = 'mysql:host=localhost;dbname=hazelnuttest';
    private const SQL_USER     = 'hazelnuttest';
    private const SQL_PASSWORD = 'hazelnuttest';

    protected function setUp() :void {
        require_once('src/SqlNutStorage.php');
        try {
            $this->pdo = new PDO(self::SQL_DSN, self::SQL_USER, self::SQL_PASSWORD);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->exec(<<<'SQL'
                CREATE TABLE unittest (
                    orig CHAR(44) NOT NULL PRIMARY KEY,
                    nut CHAR(44) NOT NULL,
                    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    network BIGINT NOT NULL,
                    host BIGINT NOT NULL,
                    tif INT UNSIGNED NOT NULL,
                    pubkey CHAR(44) DEFAULT NULL,
                    verified TINYINT NOT NULL DEFAULT 0,
                    UNIQUE (nut))
SQL);
            $this->storage = new \Varden\Hazelnut\SqlNutStorage($this->pdo, 'unittest');
            $this->configure($this->storage);
        } catch (PDOException $ex) {
            $this->markTestSkipped('Failed to connect to SQL database.');
        }
    }

    protected function tearDown() :void {
        $this->destroy();
        $this->storage = null;
        $this->pdo->exec('DROP TABLE unittest');
        $this->pdo = null;
    }
}
