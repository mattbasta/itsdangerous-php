<?php

require("itsdangerous.php");

$s = new Signer("secret");
$foo = $s->sign("hello");
echo $foo, "<br>";

$bar = $s->unsign($foo);
echo $bar, "<br>";

$ts = new TimestampSigner("another_secret");
$foo2 = $ts->sign("haldo");
echo $foo2, "<br>";

$bar2 = $ts->unsign($foo2);
echo $bar2, "<br>";

sleep(2);

echo $ts->validate($foo2), "<br>";
echo $ts->validate($foo2, 0), "<br>";

$complex = array(
    "foo",
    123,
    array(1.1, 2.2, "3.3")
);

$ser = new Serializer("asecret");
$c = $ser->dumps($complex);
echo $c, "<br>";

$cp = $ser->loads($c);
var_dump($cp);
echo "<br>";

$s2 = new Serializer("whatevs");
echo $s2->loads($c);

