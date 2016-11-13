<?php
/**
 * php version for urlchecker, to deal with tld, url stat, etc
 * 
 * see 
 * https://github.com/wushen2016/urlchecker
 * https://github.com/layershifter/TLDExtract
 *
 */
ini_set('memory_limits', '1024M');

class URLChecker_Util
{
    /**
     *
     https://tools.ietf.org/html/rfc3986
     https://tools.ietf.org/html/rfc1808

     <scheme>://<net_loc>/<path>;<params>?<query>#<fragment>

     <scheme>://<user>:<password>@<host>:<port>/<url-path>

     foo://example.com:8042/over/there?name=ferret#nose
     \_/   \______________/\_________/ \_________/ \__/
     |           |            |            |        |
     scheme     authority       path        query   fragment
     |   _____________________|__
     / \ /                        \
     urn:example:animal:ferret:nose

     the authority component is precended by a double slash ("//")
     and is terminated by the next slash ("/"), question mark ("?"), or number sign ("#") character
                                                                                            
     */
    const SCHEMA_PATTERN = '#^([a-zA-Z][a-zA-Z0-9+\-.]*:)?//#';

    const TLD_CACHED_FILE = 'tld_cached_file';
    const ALEXA_CACHED_FILE = 'alexa_cached_file';

    private $m_ary_tlds = array();
    private $m_str_alexa = null;
    private $m_ary_alexa = array();

    private $m_ary_domainInAlexaTop = array(); // this is used as a cache
    private $m_ary_domainNotInAlexaTop = array(); // this is used as a cache

    private static function checkIP($host)
    {
        return filter_var($host, FILTER_VALIDATE_IP);
    }

    public static function getArrayLastItem($ary)
    {
        $tmpAry = array_reverse($ary, True);
        return $tmpAry[0];
    }

    public static function removeScheme($oriurl)
    {
        return preg_replace(self::SCHEMA_PATTERN, '', $oriurl);
    }

    public static function isIP($host)
    {
        if (self::checkIP($host)) {
            return True;
        }

        //for those like 221.010.34.012
        $replaced = str_replace('.0', '.', $host);
        if (self::checkIP($replaced)) { 
            return True;
        }

        //for those like 192.168.001.002
        $replaced = str_replace('.00', '.', $host);
        if (self::checkIP($replaced)) {
            return True;
        }

        //may also consider those like 010.16.32.1 ==> 10.16.32.1

        return False;
    }

    /**
     * get array($host, $port, $isip)
     */
    public static function getHostInfo($oriurl)
    { 
        /*
        //can also consider to use parse_url instead
        //but need to do more check
            
        $items = parse_url($oriurl);
        var_dump($items);
        if ($items) {
            return array('host' => $items['host'],
                         'port' => $items['port'],
                         'isip' => self::isIP($host));
        }
        */
 
        //scheme://user:password@host:port/url-path 
        // ==> user:password@host:port/url-path
        $url = preg_replace(self::SCHEMA_PATTERN, '', $oriurl);

        //the authority component is precended by a double slash ("//")
        //        and is terminated by the next slash ("/"), question mark ("?"), or number sign ("#") character
        //$url = explode('/', $url)[0];
        $url = explode('/', $url);
        $url = $url[0];
        $url = explode('?', $url);
        $url = $url[0];
        $url = explode('#', $url);
        $url = $url[0];
        #now => user:password@host:port

        //remove user:password
        // ==> host:port
        $url = self::getArrayLastItem(explode("@", $url));
        
        $items = explode(':', $url);
        $host = $items[0];
        $port = '80';
        if (count($items) == 2) {
            $port = $items[1];
        }

        /*
        return array('host' => $host, 
                     'port' => $port,
                     'isip' => self::isIP($host)); 
         */
        return array($host, $port, self::isIP($host));
    }

    /**
     * desc: get web page content
     */
    public static function fetchPage($url)
    {
        return $page = utf8_encode(file_get_contents($url));
    }

    /**
     * desc: extract tlds from online page
     *
     */
    public function downloadSuffixListSource()
    {
        $page = self::fetchPage('http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1');

        $matches = array();
        $pattern = '/^(?P<tld>[.*!]*\w[\S]*)/m';
        preg_match_all($pattern, $page, $matches);
        return $matches['tld'];
    }

    /**
     * desc: get tlds by local cache or on the fly
     */
    public function getTLDS($isForceUpdate = False)
    {
        self::getTLDSByCache();
        if (empty($this->m_ary_tlds) or $isForceUpdate) {
            $ary_tlds = self::downloadSuffixListSource();
            self::saveTLDCache($ary_tlds);

            $this->m_ary_tlds = $ary_tlds;
        }

        return $this->m_ary_tlds;
    }

    private function getTLDSByCache()
    {
        if (is_file(self::TLD_CACHED_FILE)) {
            $this->m_ary_tlds = file(self::TLD_CACHED_FILE, FILE_IGNORE_NEW_LINES);
        }
    }

    private function saveTLDCache($ary_tlds)
    {
        $fw = fopen(self::TLD_CACHED_FILE, 'wb');
        foreach ($ary_tlds as $tld) {
            fwrite($fw, "$tld\n");
        }
        fclose($fw);
    }

    /**
    http://s3.amazonaws.com/alexa-static/top-1m.csv.zip

    alex_top_1m.txt is the white domain
     *
     */
    public function getAlexaTopByCache()
    {
        $aryAlexa = file(self::ALEXA_CACHED_FILE, FILE_IGNORE_NEW_LINES);
        return $aryAlexa; 
        
        /*
        $str_alexa = file_get_contents(self::ALEXA_CACHED_FILE);
        return $str_alexa;
        */
    }

    /**
     *
     */
    public function isDomainInAlexaTop($domain)
    {
        if (!$this->m_ary_alexa) {
            echo "load alexa \n";
            $this->m_ary_alexa = self::getAlexaTopByCache();
        }
        
        //cache 
        if (in_array($domain, $this->m_ary_domainInAlexaTop)) {
            return True;
        }

        //cache
        if (in_array($domain, $this->m_ary_domainNotInAlexaTop)) {
            return False;
        }
        
        $ret = in_array($domain, $this->m_ary_alexa);
        if ($ret) {
            $this->m_ary_domainInAlexaTop[] = $domain;
        } else {
            $this->m_ary_domainNotInAlexaTop[] = $domain;
        }
        return $ret;
        /*
        if (!$this->m_str_alexa) {
            $this->m_str_alexa = self::getAlexaTopByCache();
        }

        //cache 
        if (in_array($domain, $this->m_ary_domainInAlexaTop)) {
            return True;
        }

        //cache
        if (in_array($domain, $this->m_ary_domainNotInAlexaTop)) {
            return False;
        }

        $pos = strpos($this->m_str_alexa, "\n$domain\r");
        if ($pos) {
            $this->m_ary_domainInAlexaTop[] = $domain;
            return True;
        }

        $pos = strpos($this->m_str_alexa, $domain);
        if (is_bool($pos)) {
            $this->m_ary_domainNotInAlexaTop[] =  $domain;
            return False; 
        }

        //what if at the very beginning
        if (substr($this->m_str_alexa, 0, strlen("$domain\r")) == "$domain\r") {
            $this->m_ary_domainInAlexaTop[] = $domain;
            return True;
        }

        //what if at the very end
        if (substr($this->m_str_alexa, -1 * strlen("\n$domain")) == "\n$domain") {
            $this->m_ary_domainInAlexaTop[] = $domain;
            return True;
        }
        
        $this->m_ary_domainNotInAlexaTop[] = $domain;
        return False;
        */
    }

    /**
     * if 360.cn is in alexa_top, 
     *  then www.360.cn will also in
     *
     */
    public function isDirectInAlexaTop($domain, $host)
    {
        if (!self::isDomainInAlexaTop($domain)) {
            return False;
        }

        if ($domain == $host or "www.$domain" == $host) {
            return True;
        }

        return False;
    }

    /**
     * if blogspot.com in alexa_top, then xx.blogspot.com will indirectly in 
     *
     */
    public function isIndirectInAlexaTop($domain, $host)
    {
        if (!self::isDomainInAlexaTop($domain)) {
            return False;
        }

        if (self::isDirectInAlexaTop($domain, $host)) {
            return False;
        }

        return True;
    }

    /**
     * desc: get the last 2 part splitted by /
     *
     * www.so.com           ==> www.so.com
     * www.so.com/          ==> www.so.com/
     * www.so.com/a         ==> www.so.com/a
     * www.so.com/a/        ==> a/
     * www.so.com/a/b       ==> a/b
     * www.so.com/a/b/      ==> b/
     * www.so.com/a/b/c     ==> b/c
     *
     */
    public static function getPath2($url)
    {
        $items = array_reverse(explode('/', $url));

        $path2 = '';
        for ($i = min(1, count($items) - 1); $i > 0; $i--) {
            $path2 .= $items[$i];
            $path2 .= '/';
        }

        $path2 .= $items[0];

        return $path2;
    }

    /**
     * desc: get parts splitted by /,  without the first and last part
     *
     * www.so.com    ==> www.so.com
     * www.so.com/   ==> www.so.com/
     * www.so.com/a  ==> www.so.com/a
     *
     * www.so.com/a/ ==> a/
     * www.so.com/a/b ==> a/
     * www.so.com/a/b/c  ==> a/b/
     *  
     *
     */
    public static function getPath_Middle($url)
    {
        $items = explode('/', $url);
        if (count($items) < 3) {
            return $url;
        }

        $path_middle = '';
        for ($i = 1; $i <= count($items) - 2; $i++) {
            $path_middle .= $items[$i];
            $path_middle .= '/';
        }

        return $path_middle;
    }

    /**
     * desc: get the last 2th and 3rd part, splitted by /
     *
    www.baidu.com  ==> www.baidu.com
    www.baidu.com/ ==> www.baidu.com
    www.baidu.com/a ==> www.baidu.com/a    (如果不足，则为原url)
    www.baidu.com/a/ ==> www.baidu.com/a/
    www.baidu.com/a/b ==> www.baidu.com/a/b
    www.baidu.com/a/b/ ==> a/b/
    www.baidu.com/a/b/c.zip ==> a/b/
    www.baidu.com/a/b/c.aspx?downid=d  ==> a/b/

     *
     */
    public static function getPath_r2_3($url)
    {
        $items = explode('/', $url);
        if (count($items) < 4) {
            return $url;
        }

        $items = array_reverse($items);

        $path_r2_3 = '';
        for ($i = 2; $i > 0; $i--) {
            $path_r2_3 .= $items[$i];
            $path_r2_3 .= '/';
        }

        return $path_r2_3;
    }

    /*
        desc: 综合path2, path_middle, path_r2nd, path_r2_3，动态选择最优方案。
        该方案的最优评价标准——既贪婪尽可能多的聚类，同时又要避免大量的误报（避免单字段作为结果）。

        所以，需要考虑path的字段数：

        return:
        www.baidu.com
        www.baidu.com/
        www.baidu.com/a
        以上, path2, path_middle, path_r2nd, path_r2_3，均取原值

        www.baidu.com/a/
        www.baidu.com/a/b
        这里，path2有效， path_middle有效，path_r2nd有效，但因path_middle、path_r2nd为单字段，故选择path2方案

        www.baidu.com/a/b/
        www.baidu.com/a/b/c
        这里, path2有效， path_middle有效， path_r2nd有效，path_r2_3有效，但path_r2_3能获得更多的聚类，故取path_r2_3方案

        www.baidu.com/a/b/c/d
        更多情况，同上，取path_r2_3

    */
    public static function getPathBest($url)
    {
        $items = explode('/', $url);
        if (count($items) <= 2) {
            return $url;
        }

        if (count($items) == 3) {
            return self::getPath2($url);
        }

        // all >= 4
        return self::GetPath_r2_3($url);
    }

    public static function getFileType($url)
    {
        $filetype = strrchr($url, '.');
        if ($filetype) {
            //return preg_split("/[?&=]/", $filetype)[0];
            $ret = preg_split("/[?&=]/", $filetype);
            return $ret[0];
        }

        $filetype = strrchr($url, '/');
        if ($filetype) {
            return $filetype;
        }

        return $url;
    }
}

/*
testEntry();

function testEntry()
{
    global $argv;

    //echo URLChecker_Util::isIP($argv[1]);
    //var_dump(URLChecker_Util::getHostInfo($argv[1]));
    $obj = new URLChecker_Util();
    $obj->getAlexaTopByCache();
    //echo $obj->getFileType($argv[1]);
    return;
    //
    //echo $obj->isDirectInAlexaTop($argv[1], $argv[2]), "\n";
    //echo $obj->isIndirectInAlexaTop($argv[1], $argv[2]), "\n";
    echo $obj->getPath2($argv[1]), "\t";
    echo $obj->getPath_Middle($argv[1]),"\t";
    echo $obj->getPath_r2_3($argv[1]), "\t";
    echo $obj->getPathBest($argv[1]), "\n";
}
*/
