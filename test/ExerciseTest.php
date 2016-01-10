<?php

require_once 'itsdangerous.php';

class ExerciseTest extends PHPUnit_Framework_TestCase
{

    public function testSigner_signAndUnsign_shouldBeCongruent()
    {
        $s = new Signer("secret");
        $foo = $s->sign("hello");
        $this->assertEquals($foo, 'hello.7KTthSs1fJgtbigPvFpQH1bpoGA');

        $bar = $s->unsign($foo);
        $this->assertEquals($bar, 'hello');
    }

    public function testTimestampSigner_signAndUnsign_shouldBeCongruent()
    {
        $ts = new TimestampSigner("another_secret");
        $foo = $ts->sign("haldo");
        // TODO: decouple from time() so that a test like this could be done
        // $this->assertEquals($foo, 'haldo.TODO');

        $bar = $ts->unsign($foo);
        $this->assertEquals($bar, 'haldo');
    }

    public function testTimestampSigner_signAndValidate_shouldSucceed()
    {
        $ts = new TimestampSigner("another_secret");
        $foo = $ts->sign("haldo");

        $valid = $ts->validate($foo);

        $this->assertTrue($valid);
    }

    public function testTimestampSigner_signAndValidateLater_shouldFail()
    {
        // $this->markTestSkipped('Too slow!');

        $ts = new TimestampSigner("another_secret");
        $foo = $ts->sign("haldo");

        // TODO: decouple from time() so that a test like this could be done in unit time
        sleep(2);

        $valid = $ts->validate($foo, 0);

        $this->assertFalse($valid);
    }

    private $complex = array(
        "foo",
        123,
        array(1.1, 2.2, "3.3")
    );
    private $signedJSON = '["foo",123,[1.1,2.2,"3.3"]].z6C_xbVNJ1fzlWOePnZKBC-AfiQ';

    public function testSerializer_jsonDumpsAndLoads_shouldBeCongruent()
    {
        $ser = new Serializer("asecret");
        $c = $ser->dumps($this->complex);
        $this->assertEquals($c, $this->signedJSON);

        $cp = $ser->loads($c);
        $this->assertEquals($cp, $this->complex);
    }

    public function testSerializer_jsonDumpsAndLoadsWithDifferentSecret_shouldThrow()
    {
        $this->setExpectedException('BadSignature');

        $ser = new Serializer("whatevs");
        $cp = $ser->loads($this->signedJSON);
    }

}
