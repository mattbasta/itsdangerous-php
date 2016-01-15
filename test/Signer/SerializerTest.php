<?php

use ItsDangerous\Signer\Serializer;
use ItsDangerous\BadData\BadSignature;

class SerializerTest extends PHPUnit_Framework_TestCase
{
    private $complex = array(
        "foo",
        123,
        array(1.1, 2.2, "3.3")
    );
    private $unSignedJSON = '["foo",123,[1.1,2.2,"3.3"]]';
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

    public function testSerializer_load_shouldReadSignedPayloadFromFile()
    {
        $fp = fopen('php://temp', 'r+');
        fwrite($fp, $this->signedJSON);
        rewind($fp);

        $ser = new Serializer("asecret");
        $wasRead = $ser->load($fp);

        $this->assertEquals($this->complex, $wasRead);
    }

    public function testSerializer_loadUnsafe_shouldReadSignedPayloadFromFile()
    {
        $fp = fopen('php://temp', 'r+');
        fwrite($fp, $this->signedJSON);
        rewind($fp);

        $ser = new Serializer("asecret");
        $wasRead = $ser->load_unsafe($fp);

        $this->assertEquals([true, $this->complex], $wasRead);
    }

    public function testSerializer_loadUnsafeSignComplaint_shouldReturnPayloadWithFlag()
    {
        $fp = fopen('php://temp', 'r+');
        fwrite($fp, $this->unSignedJSON);
        rewind($fp);

        $ser = new Serializer("asecret", null, null, 'angrySigner');
        $wasRead = $ser->load_unsafe($fp);

        $this->assertEquals([false, $this->complex], $wasRead);
    }

    public function testSerializer_loadUnsafeSignComplaintAndBadPayload_shouldMentionThingsAreBad()
    {
        $fp = fopen('php://temp', 'r+');
        fwrite($fp, $this->unSignedJSON);
        rewind($fp);
        $angry = new angrySerializer();

        $ser = new Serializer("asecret", null, $angry, 'angrySigner');
        $wasRead = $ser->load_unsafe($fp);

        $this->assertEquals([false, null], $wasRead);
    }

    public function testSerializer_serializerThrowsAtLoads_shouldFail()
    {
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

class angrySigner {
    public function unsign($payload) {
        throw new BadSignature('no.', $payload);
    }
}
