<?php
/**
 * @covers \Varden\Hazelnut\SqlKeyStorage
 * @uses \Varden\Hazelnut\Authenticator
 * @uses \Varden\Hazelnut\Nut
 */
class SqlKeyStorageTest extends KeyStorageTestingTemplate {
    private $storage;
    private $pdo;

    private const SQL_DSN      = 'mysql:host=localhost;dbname=hazelnuttest';
    private const SQL_USER     = 'hazelnuttest';
    private const SQL_PASSWORD = 'hazelnuttest';

    protected function setUp() :void {
        require_once('src/SqlKeyStorage.php');
        try {
            $this->pdo = new PDO(self::SQL_DSN, self::SQL_USER, self::SQL_PASSWORD);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->exec(<<<'SQL'
                CREATE TABLE unittest (
                    id INT UNSIGNED AUTO_INCREMENT NOT NULL PRIMARY KEY,
                    pubkey CHAR(44) NOT NULL,
                    vuk CHAR(44) NOT NULL,
                    suk CHAR(44) NOT NULL,
                    enabled TINYINT NOT NULL DEFAULT 1,
                    UNIQUE (pubkey))
SQL);
            $this->storage = new \Varden\Hazelnut\SqlKeyStorage($this->pdo, 'unittest');
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
