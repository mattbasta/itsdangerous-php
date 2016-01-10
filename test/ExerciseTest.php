<?php

require_once('PHP/Token/Stream/Autoload.php');
require_once 'itsdangerous.php';

class ExerciseTest extends PHPUnit_Framework_TestCase
{

    public function testSigner_useNoneAlgorithm_shouldHaveNoSignature()
    {
        $algo = new NoneAlgorithm();
        $s = new Signer("secret", null, '.', null, null, $algo);
        $foo = $s->sign("hello");
        $this->assertEquals('hello.', $foo);

        $bar = $s->unsign($foo);
        $this->assertEquals('hello', $bar);
    }

    public function testHMACAlgorithm_defaultSHA1_shouldWork()
    {
        $algo = new HMACAlgorithm();
        $s = new Signer("secret", null, '.', null, null, $algo);
        $foo = $s->sign("hello");
        $this->assertEquals('hello.7KTthSs1fJgtbigPvFpQH1bpoGA', $foo);

        $bar = $s->unsign($foo);
        $this->assertEquals('hello', $bar);
    }

    public function testSigner_signAndUnsign_shouldBeCongruent()
    {
        $s = new Signer("secret");
        $foo = $s->sign("hello");
        $this->assertEquals('hello.7KTthSs1fJgtbigPvFpQH1bpoGA', $foo);

        $bar = $s->unsign($foo);
        $this->assertEquals('hello', $bar);
    }

    public function testSigner_unsignTamperedData_shouldChoke()
    {
        $this->setExpectedException('BadSignature');

        $s = new Signer("secret");
        $bar = $s->unsign('hallo.7KTthSs1fJgtbigPvFpQH1bpoGA');
    }

    public function testSigner_deriveKeyByConcat_shouldWork()
    {
        $s = new Signer("secret", 'salty', '.', 'concat');
        $foo = $s->sign("hello");
        $this->assertEquals('hello.xsKaFG-7aZBLFXwEoyVfhXy0Btk', $foo);

        $bar = $s->unsign($foo);
        $this->assertEquals('hello', $bar);
    }

    public function testSigner_deriveKeyByHMAC_shouldWork()
    {
        $s = new Signer("secret", 'salty', '.', 'hmac');
        $foo = $s->sign("hello");
        $this->assertEquals('hello.lcna0Kctpa6ne47lHrYKfTEsdew', $foo);

        $bar = $s->unsign($foo);
        $this->assertEquals('hello', $bar);
    }

    public function testSigner_deriveKeyByGarbage_shouldChoke()
    {
        $this->setExpectedException('Exception');
        $s = new Signer("secret", 'salty', '.', 'garbage');
        $foo = $s->sign("hello");
    }

    public function testSigner_validateClean_shouldBeTrue()
    {
        $foo = 'hello.7KTthSs1fJgtbigPvFpQH1bpoGA';

        $s = new Signer("secret");
        $bar = $s->validate($foo);

        $this->assertTrue($bar);
    }

    public function testSigner_validateTampered_shouldBeFalse()
    {
        $foo = 'hillo.7KTthSs1fJgtbigPvFpQH1bpoGA';

        $s = new Signer("secret");
        $bar = $s->validate($foo);

        $this->assertFalse($bar);
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
        $this->markTestSkipped('Too slow!');

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
    private $tamperedJSON = '["foo",122,[1.1,2.2,"3.3"]].z6C_xbVNJ1fzlWOePnZKBC-AfiQ';

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

    public function testSerializer_jsonDumpsAndLoadsTamperedData_shouldFail()
    {
        $this->setExpectedException('BadSignature');

        $ser = new Serializer("asecret");
        $cp = $ser->loads($this->tamperedJSON);
    }

    public function testSerializer_serializerThrows_shouldFail()
    {
        // $this->markTestIncomplete('Upstream has + instead of . for string concat.'.
        //     ' Need to fix that and update ths test.');

        $this->setExpectedException('BadPayload');
        $angry = new angrySerializer();

        $ser = new Serializer("asecret", 'itsdangerous', $angry);
        $cp = $ser->loads('["hello":"there"].R3uKor5hg5Eh96fmCJ0Aic-BHaU');
    }

}

class angrySerializer {
    public function loads($input) {throw new Exception('no.');}
    public function dumps($input) {return 'no.';}
}
