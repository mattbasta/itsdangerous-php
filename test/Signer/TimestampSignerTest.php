<?php

use Carbon\Carbon;
use ItsDangerous\Signer\TimestampSigner;

class TimestampSignerTest extends PHPUnit_Framework_TestCase
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

    public function testTimestampSigner_wantTimestampReturned_shouldReturnTimestamp()
    {
        $nowString = '2016-01-10 08:12:31';
        $now = new Carbon($nowString);
        Carbon::setTestNow($now);

        $ts = new TimestampSigner("another_secret");
        $foo = $ts->sign("haldo");
        $this->assertEquals($foo, 'haldo.CXOj7w.soK7_HnTROV4Lew0zlxDV0mUE8I');

        $bar = $ts->unsign($foo, 30, true);
        $this->assertEquals($bar[0], 'haldo');
        $this->assertEquals($bar[1], $now);
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

}
