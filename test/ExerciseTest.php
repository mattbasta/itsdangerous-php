<?php

use Carbon\Carbon;
use ItsDangerous\Signer\TimestampSigner;
use ItsDangerous\Signer\Serializer;

require_once 'itsdangerous.php';

class ExerciseTest extends PHPUnit_Framework_TestCase
{

    public function tearDown()
    {
        Carbon::setTestNow();
    }



    public function testTimestampSigner_signAndUnsign_shouldBeCongruent()
    {
        $nowString = '2016-01-10 08:12:31';
        Carbon::setTestNow(new Carbon($nowString));

        $ts = new TimestampSigner("another_secret");
        $foo = $ts->sign("haldo");
        $this->assertEquals($foo, 'haldo.CXOj7w.soK7_HnTROV4Lew0zlxDV0mUE8I');

        $bar = $ts->unsign($foo);
        $this->assertEquals($bar, 'haldo');
    }

    public function testTimestampSigner_signAndValidate_shouldSucceed()
    {
        $ts = new TimestampSigner("another_secret");
        $foo = $ts->sign("haldo");

        $valid = $ts->validate($foo, 30);

        $this->assertTrue($valid);
    }

    public function testTimestampSigner_signAndValidateLater_shouldFail()
    {
        $nowString = '2016-01-10 08:12:31';
        Carbon::setTestNow(new Carbon($nowString));

        $ts = new TimestampSigner("another_secret");
        $foo = $ts->sign("haldo");

        // an hour later...
        $nowString = '2016-01-10 09:12:31';
        Carbon::setTestNow(new Carbon($nowString));

        // 30 minute expiry
        $valid = $ts->validate($foo, 30);

        $this->assertFalse($valid);
    }

    public function testTimestampSigner_unsignTamperedData_shouldFail()
    {
        $this->setExpectedException('ItsDangerous\BadData\BadTimeSignature');

        $nowString = '2016-01-10 08:12:31';
        Carbon::setTestNow(new Carbon($nowString));

        $ts = new TimestampSigner("another_secret");
        $ts->unsign('haldo.CXOj7v.soK7_HnTROV4Lew0zlxDV0mUE8I');
    }

    public function testTimestampSigner_unsignMissingTimestamp_shouldFail()
    {
        $this->setExpectedException('ItsDangerous\BadData\BadTimeSignature');

        $nowString = '2016-01-10 08:12:31';
        Carbon::setTestNow(new Carbon($nowString));

        $ts = new TimestampSigner("secret");
        $ts->unsign('hello.7KTthSs1fJgtbigPvFpQH1bpoGA');
    }

    public function testTimestampSigner_unsignMissingTimestampTampered_shouldFail()
    {
        $this->setExpectedException('ItsDangerous\BadData\BadSignature');

        $nowString = '2016-01-10 08:12:31';
        Carbon::setTestNow(new Carbon($nowString));

        $ts = new TimestampSigner("secret");
        $ts->unsign('hillo.7KTthSs1fJgtbigPvFpQH1bpoGA');
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
        $this->assertEquals($this->complex, $cp);
    }

    public function testSerializer_jsonLoadsWithDifferentSecret_shouldThrow()
    {
        $this->setExpectedException('ItsDangerous\BadData\BadSignature');

        $ser = new Serializer("whatevs");
        $cp = $ser->loads($this->signedJSON);
    }

    public function testSerializer_jsonLoadsTamperedData_shouldFail()
    {
        $this->setExpectedException('ItsDangerous\BadData\BadSignature');

        $ser = new Serializer("asecret");
        $cp = $ser->loads($this->tamperedJSON);
    }

    public function testSerializer_dump_shouldWriteSignedPayloadDumpToFile()
    {
        $fp = fopen('php://temp', 'r+');

        $ser = new Serializer("asecret");
        $ser->dump($this->complex, $fp);

        rewind($fp);
        $wasWritten = fread($fp, 8192);
        $this->assertEquals($this->signedJSON, $wasWritten);
    }

    // TODO: the method this tests is broken.
    // public function testSerializer_load_shouldReadSignedPayloadFromFile()
    // {

    //     $fp = fopen('php://temp', 'r+');
    //     fwrite($fp, $this->signedJSON);
    //     rewind($fp);

    //     $ser = new Serializer("asecret");
    //     $wasRead = $ser->load($tmpfname);

    //     $this->assertEquals($this->complex, $wasRead);
    // }

    public function testSerializer_serializerThrowsAtLoads_shouldFail()
    {
        // $this->markTestIncomplete('Upstream has + instead of . for string concat.'.
        //     ' Need to fix that and update ths test.');

        $this->setExpectedException('ItsDangerous\BadData\BadPayload');
        $angry = new angrySerializer();

        $ser = new Serializer("asecret", 'itsdangerous', $angry);
        $cp = $ser->loads($this->signedJSON);
    }

    public function testSerializer_loadsUnsafe_happyFunFunTime()
    {
        $ser = new Serializer("asecret");
        $cp = $ser->loads_unsafe($this->signedJSON);
        $this->assertEquals([true, $this->complex], $cp);
    }

    public function testSerializer_loadsUnsafeWrongSecret_shouldNoteUntrustworthy()
    {
        $ser = new Serializer("notasecret");
        $cp = $ser->loads_unsafe($this->signedJSON);
        $this->assertEquals([false, $this->complex], $cp);
    }

    public function testSerializer_loadsUnsafeTamperedData_shouldNoteUntrustworthy()
    {
        $ser = new Serializer("asecret");
        $cp = $ser->loads_unsafe($this->tamperedJSON);
        $this->assertEquals(false, $cp[0]);
    }

    public function testSerializer_loadsUnsafeExplodingTeaPot_shouldNoteThatSomethingBeWrong()
    {
        $angry = new angrySerializer();

        $ser = new Serializer("asecret", 'itsdangerous', $angry);
        $cp = $ser->loads_unsafe($this->signedJSON);
    }

    public function testSerializer_loadsUnsafeBadSalt_shouldNoteThatSomethingBeWrong()
    {
        $angry = new angrySerializer();

        $ser = new Serializer("asecret", 'itsdangerous', $angry);
        $cp = $ser->loads_unsafe($this->signedJSON);
    }

}

class angrySerializer {
    public function loads($input) {throw new Exception('no.');}
    public function dumps($input) {return 'no.';}
}
