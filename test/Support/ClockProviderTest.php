<?php

use ItsDangerous\Support\ClockProvider;

class ClockProviderTest extends PHPUnit_Framework_TestCase
{
    public function testGetTimestamp_default_shouldGetNow()
    {
        $dt = new DateTime();
        $dtnow = $dt->getTimestamp() - ClockProvider::$EPOCH;

        $cpnow = ClockProvider::getTimestamp();

        $this->assertEquals($dtnow, $cpnow);
    }

    public function testGetTimestamp_timestampFromPassedDate()
    {
        $dt = new DateTime('August 10, 2020 3:00p');
        ClockProvider::setTestNow($dt);

        $testnow = ClockProvider::getTimestamp();

        $this->assertEquals($dt->getTimestamp() - ClockProvider::$EPOCH, $testnow);
    }

    public function testTimestampToDate_suchMagic()
    {
        $dt = new DateTime('August 10, 2020 3:00p');
        $timestamp = $dt->getTimestamp() - ClockProvider::$EPOCH;

        $dtft = ClockProvider::timestampToDate($timestamp);

        $this->assertEquals($dt, $dtft);
    }
}
