<?php

use ItsDangerous\Support\ClockProvider;
use ItsDangerous\Signer\TimedSerializer;

class TimedSerializerTest extends PHPUnit_Framework_TestCase
{
    private $nowString, $now;
    private $complex = array(
        "foo",
        123,
        array(1.1, 2.2, "3.3")
    );
    private $signedJSON = '["foo",123,[1.1,2.2,"3.3"]]' . //payload
                          '.CXOj7w' . // timestamp
                          '.csPnVJixr4Z3sRRuDzHBz7l8mKo'; //signature
    private $tamperedJSON = '["foo",123,[1.1,2.2,"3.4"]]' . //payload
                          '.CXOj7w' . // timestamp
                          '.csPnVJixr4Z3sRRuDzHBz7l8mKo'; //signature

    public function setUp()
    {
        $this->nowString = '2016-01-10 08:12:31';
        $this->now = new DateTime($this->nowString);
        ClockProvider::setTestNow($this->now);
    }

    public function tearDown()
    {
        ClockProvider::setTestNow();
    }

    public function testDefaultSigner_usesTimedSigner()
    {
        $ser = new TimedSerializer("asecret");
        $c = $ser->dumps($this->complex);

        $this->assertEquals($this->signedJSON, $c);
    }

    public function testLoads_validPayload_extractsHappily()
    {
        $ser = new TimedSerializer("asecret");
        $c = $ser->loads($this->signedJSON);

        $this->assertEquals($this->complex, $c);
    }

    public function testLoads_validPayload_extractsWithTimestamp()
    {
        $ser = new TimedSerializer("asecret");
        $c = $ser->loads($this->signedJSON, null, true);

        $this->assertEquals([$this->complex, $this->now], $c);
    }

    public function testLoads_expiredPayload_ShouldComplain()
    {
        $this->setExpectedException('ItsDangerous\BadData\SignatureExpired');

        $nowString = '2016-01-10 08:13:31';
        ClockProvider::setTestNow(new DateTime($nowString));

        $ser = new TimedSerializer("asecret");
        $c = $ser->loads($this->signedJSON, 30);
    }

    public function testLoadsUnsafe_validPayload_extractsHappily()
    {
        $ser = new TimedSerializer("asecret");
        $c = $ser->loads_unsafe($this->signedJSON);

        $this->assertEquals([true, $this->complex], $c);
    }

    public function testLoadsUnsafe_wrongSecret_shouldNoteUntrustworthy()
    {
        $ser = new TimedSerializer("notasecret");
        $cp = $ser->loads_unsafe($this->signedJSON);
        $this->assertEquals([false, $this->complex], $cp);
    }

    public function testLoadsUnsafe_tamperedData_shouldNoteUntrustworthy()
    {
        $ser = new TimedSerializer("asecret");
        $cp = $ser->loads_unsafe($this->tamperedJSON);
        $this->assertEquals(false, $cp[0]);
    }

    public function testLoadsUnsafe_explodingTeaPot_shouldNoteThatSomethingBeWrong()
    {
        $angry = new angrySerializer();

        $ser = new TimedSerializer("asecret", 'itsdangerous', $angry);
        $cp = $ser->loads_unsafe($this->signedJSON);

        $this->assertEquals([false, null], $cp);
    }

    public function testLoadUnsafe_signComplaintAndBadPayload_shouldMentionThingsAreBad()
    {
        $angry = new angrySerializer();

        $ser = new TimedSerializer("asecret", null, $angry, 'angrySigner');
        $wasRead = $ser->loads_unsafe($this->signedJSON);

        $this->assertEquals([false, null], $wasRead);
    }

    public function testLoad_readSignedPayloadFromFile_shouldDoIt()
    {
        $fp = fopen('php://temp', 'r+');
        fwrite($fp, $this->signedJSON);
        rewind($fp);

        $ser = new TimedSerializer("asecret");
        $wasRead = $ser->load($fp);

        $this->assertEquals($this->complex, $wasRead);
    }

    public function testLoad_expiredFromFile_shouldComplain()
    {
        $fp = fopen('php://temp', 'r+');
        fwrite($fp, $this->signedJSON);
        rewind($fp);

        $this->setExpectedException('ItsDangerous\BadData\SignatureExpired');

        $nowString = '2016-01-10 08:13:31';
        ClockProvider::setTestNow(new DateTime($nowString));


        $ser = new TimedSerializer("asecret");
        $wasRead = $ser->load($fp, 30);
    }

    public function testLoad_wantTimeStamp_returnTimestamp()
    {
        $fp = fopen('php://temp', 'r+');
        fwrite($fp, $this->signedJSON);
        rewind($fp);

        $ser = new TimedSerializer("asecret");
        $wasRead = $ser->load($fp, null, true);

        $this->assertEquals([$this->complex, $this->now], $wasRead);
    }

    public function testLoadUnsafe_validPayload_extractsHappily()
    {
        $fp = fopen('php://temp', 'r+');
        fwrite($fp, $this->signedJSON);
        rewind($fp);

        $ser = new TimedSerializer("asecret");
        $c = $ser->load_unsafe($fp);

        $this->assertEquals([true, $this->complex], $c);
    }


}
