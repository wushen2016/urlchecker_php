<?php
require_once (__DIR__ . '/urlchecker_util.php');

class URLChecker_Extractor
{
    private $m_ary_tlds = null;

    public function __construct()
    {
        $obj_util = new URLChecker_Util();
        $this->m_ary_tlds = $obj_util->getTLDS();
    }
    
    public function __destruct()
    {
        $this->m_ary_tlds = null;
        unset($this->m_ary_tlds);
    }

    /**
     * desc:  netloc is the host
     *
     * return: array(registereddoamin, tld)
     */
    public function extract($netloc)
    {
        $parts = explode('.', strtolower($netloc));

        for ($i = 0, $cnt = count($parts);
             $i < $cnt;
             $i++) {
            $maybe_tld = implode('.', array_slice($parts, $i));

            /*
            http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1
             
             *.ck
             !www.ck

             so, 
             www.ck ==> ('www', 'ck')
             any.ck ==> ('', 'any.ck')
             */
            $exception_tld = '!' . $maybe_tld;
            if (in_array($exception_tld, $this->m_ary_tlds)) {
                $register_domain = implode('.', array_slice($parts, 0, $i+1));
                $tld = implode('.', array_slice($parts, $i+1));
                return array($register_domain, $tld);
            }

            if (in_array($maybe_tld, $this->m_ary_tlds)) {
                $reg = implode('.', array_slice($parts, 0, $i));
                $tld = implode('.', array_slice($parts, $i));
                return array($reg, $tld);
            }
    
            $wildcard_tld = '*.' . implode('.', array_slice($parts, $i+1));
            if (in_array($wildcard_tld, $this->m_ary_tlds)) {
                $reg = implode('.', array_slice($parts, 0, $i));
                $tld = implode('.', array_slice($parts, $i));
                return array($reg, $tld);
            }
        }//end for
        return array('', $netloc);
    }
}

/*
testEntry();

function testEntry()
{
    global $argv;
    $obj = new URLChecker_Extractor();
    var_dump($obj->extract($argv[1]));
}
*/
