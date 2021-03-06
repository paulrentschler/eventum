<?php

class DbApiTest extends PHPUnit_Framework_TestCase
{
    public function testPearApi()
    {
        if (getenv('TRAVIS')) {
            $this->markTestSkipped('Test requires database');
        }

        $config = DB_Helper::getConfig();
        $instance = new DbPear($config);
        $this->assertNotNull($instance);
    }

    public function testNullApi()
    {
        $config = DB_Helper::getConfig();
        $instance = new DbNull($config);
        $this->assertNotNull($instance);
    }
}
