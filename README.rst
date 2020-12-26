Hazelnut
========

Hazelnut is a native PHP implementation of the SQRL authentication protocol. It is designed to be easy to implement, with modular storage backend support.

Usage
-----

First, you'll have to include the PHP files and configure the authenticator:

.. code-block:: php

   // Include required modules - Hazelnut itself, plus one key storage and one
   // nut storage provider
   require_once('Hazelnut.php');
   require_once('SqlKeyStorage.php');
   require_once('SqlNutStorage.php');

   // Configure the authenticator (SQL example)
   $pdo = new \PDO('mysql:host=localhost;dbname=MySqrlApp', 'user', 'password');
   $keyStorage = new \Varden\Hazelnut\SqlKeyStorage($pdo, 'sqrlkeys');
   $nutStorage = new \Varden\Hazelnut\SqlNutStorage($pdo, 'sqrlnuts');
   $auth = new \Varden\Hazelnut\Authenticator($keyStorage, $nutStorage);
   $auth
       -> setSite('example.com')
       -> setAuthPath('/sqrlauth.php')
       -> setFriendlyName('Your app name here');

Now, you can create a session for authentication, and generate a SQRL URI that
can be e.g. made into a QR code:

.. code-block:: php

   // Create a session and store it
   session_start();
   $session = $auth->createAuthSession();
   $_SESSION['sqrlid'] = $session;

   // Echo the SQRL URI (or pass it to a QR library to make a scannable code):
   echo $auth->getSqrlUri($session);

The above example assumes you have a ``/sqrlauth.php`` file. This would contain
the verification code. Configure the authenticator the same way, and simply add
this call to automatically handle the incoming request, and produce a response.

.. code-block:: php

   $auth->handleRequest();

To check if a user is successfully authenticated, you can use:

.. code-block:: php

   session_start();
   if (!isset($_SESSION['sqrlid'])) echo "No session";
   else if (!$auth->isAuthenticated($_SESSION['sqrlid'])) echo "Not logged in";
   else echo "Successfully authenticated";

Options
-------

``setSite(string $site)``
   Sets the domain and, if applicable, path to the root of your web application.
   This can be either just a domain name (e.g. ``example.com``) or a path to the
   root of your app (e.g. ``example.com/apps/myapp``). Defaults to
   ``$_SERVER['HTTP_HOST']``.

``setAuthPath(string $path)``
   Sets the path to the SQRL CLI endpoint (the file that contains the
   ``handleRequest`` call), which is appended to your site. E.g. if you set your
   site to ``example.com/apps/myapp`` and your auth path to ``/sqrlauth.php``,
   the full URL would therefore be
   ``http(s)://example.com/apps/myapp/sqrlauth.php``.

``setSecure(bool $secure)``
   Sets whether the authenticator should make SQRL (secure) or QRL (insecure)
   URIs. Defaults to autodetection via ``$_SERVER['HTTPS']`` - you should change
   this manually if you are using e.g. a reverse proxy or TLS terminator in
   front of your webserver.

``setRemoteIP(string $ip)``
   Sets the IP address of the connecting user. Defaults to
   ``$_SERVER['REMOTE_ADDR']``. You must change this if you are using a reverse
   proxy, load balancer etc. in front of your web server. Must be a single,
   valid IPv4 or IPv6 address.

``setFriendlyName(string $name)``
   Sets the human-readable name of your site. Not set by default (i.e. your site
   domain is showed to users instead).

``setExpiryMinutes(int $minutes)``
   Sets the time-to-live (TTL) of each authentication session. This is the
   maximum amount of time allowed before the QR code expires, and thus the time
   by which a user must have authenticated. Defaults to 5 minutes.

Storage providers
-----------------

SQL
^^^

First, create two tables - they don't have to have these specific names, as long
as the structure is the same:

.. code-block:: sql

   CREATE TABLE sqrlkeys (
       id INT UNSIGNED AUTO_INCREMENT NOT NULL PRIMARY KEY,
       pubkey CHAR(44) NOT NULL,
       vuk CHAR(44) NOT NULL,
       suk CHAR(44) NOT NULL,
       enabled TINYINT NOT NULL DEFAULT 1,
       UNIQUE (pubkey))

   CREATE TABLE sqrlnuts (
       orig CHAR(44) NOT NULL PRIMARY KEY,
       nut CHAR(44) NOT NULL,
       created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
       network BIGINT NOT NULL,
       host BIGINT NOT NULL,
       tif INT UNSIGNED NOT NULL,
       pubkey CHAR(44) DEFAULT NULL,
       verified TINYINT NOT NULL DEFAULT 0,
       UNIQUE (nut))

Then, include the SQL providers and configure them to use those tables:

.. code-block:: php

   $pdo = new \PDO('mysql:host=localhost;dbname=sqrldatabase', 'username', 'password');
   $keyStorage = new \Varden\Hazelnut\SqlKeyStorage($pdo, 'sqrlkeys');
   $nutStorage = new \Varden\Hazelnut\SqlNutStorage($pdo, 'sqrlnuts');

You can now pass ``$keyStorage`` and ``$nutStorage`` to the Authenticator
constructor.
