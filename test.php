<?php

require("itsdangerous.php");

define("NL", (php_sapi_name() == 'cli') ? "\n" : "<br />");

$s = new Signer("secret");
$foo = $s->sign("hello");
echo $foo, NL;

$bar = $s->unsign($foo);
echo $bar, NL;

$ts = new TimestampSigner("another_secret");
$foo2 = $ts->sign("haldo");
echo $foo2, NL;

$bar2 = $ts->unsign($foo2);
echo $bar2, NL;

sleep(2);

echo $ts->validate($foo2), NL;
echo $ts->validate($foo2, 0), NL;

$complex = array(
    "foo",
    123,
    array(1.1, 2.2, "3.3")
);

$ser = new Serializer("asecret");
$c = $ser->dumps($complex);
echo $c, NL;

$cp = $ser->loads($c);
var_dump($cp);
echo NL;

$s2 = new Serializer("whatevs");
try {
    echo $s2->loads($c), NL;
    echo "FAILED", NL;
} catch (Exception $e){
    echo $e->getMessage(), NL, NL;
}

$s1 = new URLSafeSerializer("secret");
$c = $s1->dumps($complex);
echo $c, NL;
var_dump($s1->loads($c));
echo NL;

$s1 = new URLSafeTimedSerializer("secret");
$c = $s1->dumps($complex);
echo $c, NL;
var_dump($s1->loads($c));
echo NL;
