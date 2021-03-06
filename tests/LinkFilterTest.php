<?php

class LinkFilterTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (getenv('TRAVIS')) {
            $this->markTestSkipped("No DB tests in Travis");
        }
    }

    /**
     * @dataProvider testIssueLinking_data
     * @see          Link_Filter::proccessText
     */
    public function testIssueLinking($text, $exp)
    {
        $filters = Link_Filter::getFilters();

        foreach ((array)$filters as $filter) {
            list($pattern, $replacement) = $filter;
            // replacement may be a callback, provided by workflow
            if (is_callable($replacement)) {
                $text = preg_replace_callback($pattern, $replacement, $text);
            } else {
                $text = preg_replace($pattern, $replacement, $text);
            }
        }

        $this->assertRegExp($exp, $text);
    }

    public function testIssueLinking_data()
    {
        return array(
            0 => array(
                'issue #1',
                '; <a title="issue 1.*" class="" href="view.php\?id=1">issue #1</a>;'
            ),
            1 => array(
                'Issue: 1',
                '; <a title="issue 1.*" class="" href="view.php\?id=1">Issue: 1</a>;'
            ),
            2 => array(
                'issue 1',
                '; <a title="issue 1.*" class="" href="view.php\?id=1">issue 1</a>;'
            ),
        );
    }
}
