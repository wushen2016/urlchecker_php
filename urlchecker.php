<?php
require_once (__DIR__ . '/urlchecker_extractor.php');
require_once (__DIR__ . '/urlchecker_util.php');

class URLChecker
{
    private $m_extractor = null;
    private $m_util = null;
    private $m_ary_domain_hosts = array(); #{domain:[hosts], }
    private $m_ary_inAlexa = array();  // {'host':['direct', url1, url2,....

    public function __construct()
    {
        $this->m_extractor = new URLChecker_Extractor();
        $this->m_util = new URLChecker_Util();
    }

    public function __destruct()
    {
    }

    public static function str_rpartition($haystack, $needle)
    {
        $index = strrpos($haystack, $needle);
        if (is_bool($index)) {
            return array('', $needle, $haystack);
        }

        return array(substr($haystack, 0, $index), $needle, substr($haystack, $index + strlen($needle)));
    }

    /**
     * desc: 1) find the last FQDN
     *       2) if no FQDN exist, find the last ip

     #10.102.3.20/update/files/31710000007F3D77/down.myapp.com/myapp/smart_ajax/com.tencent.android.qqdownloader/991310_22331408_1451062634607.apk
         => down.myapp.com
                           
     #10.236.6.15/downloadw.inner.bbk.com/sms/upapk/0/com.bbk.appstore/20151009151923/com.bbk.appstore.apk
        => download.inner.bbk.com

     *
     */
    public function removeCDN($oriurl)
    {
        $url = URLChecker_Util::removeScheme($oriurl);

        $parts = explode('/', $url);
        $cnt = count($parts);
        $tmpItems = array_slice($parts, 0, $cnt - 1);
        
        $items = array();
        foreach ($tmpItems as $tmp) {
            if (strstr($tmp, '.') and !strstr($tmp, '&') and !strstr($tmp, '?')) {
                $items[] = $tmp;
            }
        }

        if (empty($items)) {
            $items = array($url);
        } 

        $lastip = null;
        foreach (array_reverse($items) as $item) {  
            list($host, $port, $subhost, $domain, $tld, $isip, $isValidDomain) = self::getHostInfo($item, False);

            #45.79.146.48/admin201506/uploadApkFile/rt/20160113/geniusalldata.zip
            if (substr($host, -4) == '.zip') {
                continue;
            }
            
            #buckets.apps.tclclouds.com/appstore/apk/com.tencent.mm/com.tencent.mm.apk
            #downloadw.inner.bbk.com/sms/upapk/4096/com.iqoo.secure/20161024173040/com.iqoo.secure.apk
            #saufs.coloros.com/patch/CHN/com.oppo.market/5004/com.oppo.market_5.0_5004_all_1610281508.apk
            if (substr($host, 0, 3) == 'com') {
                continue;
            }

            //the last valid FQDN
            if ($isValidDomain and !$isip) {
                //errors can be here
                //like  domain.com/xxx/domain.com&id=1   ==> domain.com&id=1
                $ret = self::str_rpartition($url, $host);
                return $host . $ret[2];
            }

            //record the lastip
            if ($isip and !$lastip) {
                $lastip = $host;
            }
        }//

        if ($lastip) {
            $ret = self::str_rpartition($url, $lastip);
            return $lastip . $ret[2];
        }

        return $url;
    }

    /**
     * desc: oriurl can be a url, host
     *
     * return: (host, port, domain, tld, isip, isvalidDomain)
     *
     * Note:  host is FQDN, or you can call it subdomain, 
     *        like www.360.cn is host, 
     *             360.cn is domain
     *          
     */
    public function getHostInfo($oriurl, $needremovecdn = True)
    {
        $isValidDomain = True;
        $url = $oriurl;
        
        if ($needremovecdn) {
            $url = self::removeCDN($url);
        }
    
        list($host, $port, $isip) = URLChecker_Util::getHostInfo($url); 
        if ($isip) {
            return array($host, $port, $host, $host, '', $isip, $isValidDomain);
        }

        list($registered_domain, $tld) = $this->m_extractor->extract($host);
        list($subdomain, $tmp, $domain) = self::str_rpartition($registered_domain, '.');
        $domain = "{$domain}.{$tld}";
        //echo "{$registered_domain}\t$tld\t$host\n";
        //echo "$subdomain, $tmp, $domain\n";
        //echo "$domain\n";

        /**
        *.ck
        !www.ck

        so do.ck 's tld is '.do.ck', 

        221.220.221.1998  's domain will be '1998.'

        thz invalid domain starts or ends with '.'
        */
        if ($domain[0] == '.' or substr($domain, -1) == '.' 
            //com&cuid=820231&fext=.zip
            or strstr($domain, '&') or strstr($domain, '=')) {
            $isValidDomain = False;
        }
        
        /*
         *  www.so.com is host, or FQDN
         *      so.com is domain
         *      www  is considered as subhost
         */
        $subhost = strstr($host, $domain, True);
        return array($host, $port, $subhost, $domain, $tld, $isip, $isValidDomain);
    }

    /**
     * desc: to dump some suspicious urls, by doing some statistics about domain_hosts
     *      针对一定观察期内的urls, 做些domain_hosts的初步统计，产出url规则
     *      主要适用于host多变、恶意传播类型
     *
     *  判定策略如下：
     *  1）domain 不在alexa_top中
     *  2）cnt_hosts比较大， 其代表着多变性，可能开启了泛解析， 设定阈值
     *  3）各hosts的长度尽可能模式一致，可用长度范围限定，最大、最小及差异， 设定阈值
     *  4）filetype比较收敛，cnt_filetype, 设定阈值
     *  5）filetype的具体类别， 观察历史周期内可能出现问题的类型
     *  6）cnt_urls  该domain下所有url的条数，代表了触发量、流行度
     *  7) url关键词，这些关键词，是增强作用，像%, se, rt, root之类
     *
     */
    public function dumpSuspiciousURL_Domain_Hosts($filename) 
    {
        self::doStat_Domain_Hosts($filename);

        $fw = fopen("dump_suspicious_{$filename}.txt", 'wb');
        foreach ($this->m_ary_domain_hosts as $domain => $hostInfo) {
            if ($hostInfo['isInAlexaTop']) {
                continue;
            }

            //define your own suspicious rule

            $infoAry = array($domain, $hostInfo['urls'][0]);
            fwrite($fw, implode('|', $infoAry) . "\n");

            //now can also insert into DB
        }
        fclose($fw);
    }
    
    /**
     * desc: simply do statistics about domain_hosts info
     *       and info about alexa top
     *       and maintain the lines for each domain, used for more processing
     */ 
    private function doSimpleStat_Domain_Hosts($filename)
    {
        $fr = fopen($filename, "rb");
        if (!$fr) {
            return False;
        }

        $ary_domain_hosts = array();
        $ary_inAlexaTop   = array();
        $isInAlexaTop = False;

        $index = 0;
        while ($line = fgets($fr)) {
            $line = trim($line);

            list($host, $port, $subhost,$domain, $tld, $isip, $isValidDomain) = self::getHostInfo($line);

            if (!array_key_exists($domain, $ary_domain_hosts)) {
                $isInAlexaTop = $this->m_util->isDomainInAlexaTop($domain);

                $ary_domain_hosts[$domain] = array('isip' => $isip,
                                                    'isvaliddomain' => $isValidDomain,
                                                    'isInAlexaTop'  =>  $isInAlexaTop,
                                                    'cnt_hosts' => 0,
                                                    'hosts' => array(),
                                                    'lines' => array(),
                                                );
            }
            $ary_domain_hosts[$domain]['hosts'][] = $host;
            $ary_domain_hosts[$domain]['lines'][] = $index;
            $index += 1;

            if (!$isInAlexaTop) {
                continue;
            }

            //deal with those urls that directly in or indirectly in Alexa
            $directInAlexa = $this->m_util->isDirectInAlexaTop($domain, $host);
            $inDirectInAlexa = $this->m_util->isInDirectInAlexaTop($domain, $host);

            $in = 'direct';
            if ($inDirectInAlexa) {
                $in = 'indirect';
            }

            if (!array_key_exists($host, $ary_inAlexaTop)) {
                $ary_inAlexaTop[$host] = array(
                                           'domain' => $domain,
                                           'inAlexa' => $in,
                                           'urls' => array()); 
            }
            $ary_inAlexaTop[$host]['urls'][] = $line;
        } 

        foreach ($ary_domain_hosts as $domain => $hostInfo) {
            $uniq_hosts = array_unique($hostInfo['hosts']);
            $ary_domain_hosts[$domain]['hosts'] = $uniq_hosts;
            $ary_domain_hosts[$domain]['cnt_hosts'] = count($uniq_hosts);
        }

        URLChecker::arrayMultiSort($ary_domain_hosts, 'cnt_hosts', SORT_DESC);
        return array($ary_domain_hosts, $ary_inAlexaTop);
    }

    /**
     * desc: 
     *
     */
    public function dumpSimpleStat_Domain_Hosts($filename)
    {
        list($ary_domain_hosts, $ary_inAlexaTop) = self::doSimpleStat_Domain_Hosts($filename);

        $fw_domain_hosts = fopen("{$filename}_domain_hosts.txt", "wb");
        foreach ($ary_domain_hosts as $domain => $hostInfo) {
            if ($hostInfo['isInAlexaTop']) {
                continue;
            }

            if ($hostInfo['isip']) {
                continue;
            }

            $valid = '';
            if (!$hostInfo['isvaliddomain']) {
                $valid = 'invalid';
            }
            
            $infoAry = array($domain, $hostInfo['cnt_hosts'], $valid, '_domain_'); 
            fwrite($fw_domain_hosts,  implode("\t", $infoAry) . "\n");
            foreach ($hostInfo['hosts'] as $host) {
                fwrite($fw_domain_hosts, "\t$host\n");
            }
        }
        fclose($fw_domain_hosts);

        $fw_direct = fopen("{$filename}_directinalexa.txt", "wb");
        $fw_indirect = fopen("{$filename}_indirectinalexa.txt", "wb");
        foreach ($ary_inAlexaTop as $host => $hostInfo) {
            $in = $hostInfo['inAlexa'];
            $fw = $fw_direct;
            if ($in == 'indirect') {
                $fw = $fw_indirect;
            }

            foreach ($hostInfo['urls'] as $url) {
                $infoAry = array($hostInfo['domain'], $host, $url);
                fwrite($fw, implode("\t", $infoAry) . "\n");
            }
        }
        fclose($fw_direct);
        fclose($fw_indirect);
    }

    /**
     * desc: filename contains the hosts or urls
     *    
     *       do some stat about all domains, hosts
     */
    public function doStat_Domain_Hosts($filename)
    {
        if ($this->m_ary_domain_hosts) {
            return;
        }

        $fr = fopen($filename, "rb");
        if (!$fr) {
            return False;
        }

        while ($line = fgets($fr)) {
            $line = trim($line);

            list($host, $port, $subhost,$domain, $tld, $isip, $isValidDomain) = self::getHostInfo($line);

            if (!array_key_exists($domain, $this->m_ary_domain_hosts)) {
                $this->m_ary_domain_hosts[$domain] = array('isip' => $isip,
                                                           'isvaliddomain' => $isValidDomain,
                                                           'isInAlexaTop'  => $this->m_util->isDomainInAlexaTop($domain),
                                                           'cnt_hosts' => 0,
                                                           'host_max_len' => strlen($host),
                                                           'host_min_len' => strlen($host),
                                                           'sub_max_len' => 0,  // subhost
                                                           'hosts' => array(),
                                                           'cnt_urls'  => 0,
                                                           'urls' => array(),  //only one for each filetype
                                                           'filetype' => array(),
                                                           'cnt_filetype' => 0,
                                                           'percent_part_host' => 0.0,  //max part splitted by . for host
                                                           'percent_host_url' => 0.0,  // len_host / len_url
                                                       );
            }
            array_push($this->m_ary_domain_hosts[$domain]['hosts'], $host);
            $this->m_ary_domain_hosts[$domain]['sub_max_len'] = max($this->m_ary_domain_hosts[$domain]['sub_max_len'],
                                                                    max(array_map('strlen', explode('.', $subhost))));
            
            $this->m_ary_domain_hosts[$domain]['cnt_urls'] += 1;

            //whether need to maintain the urls relationship
            //array_push($this->m_ary_domain_hosts[$domain]['urls'], $line);
            $filetype = $this->m_util->getFileType($line);
            if (!in_array($filetype, $this->m_ary_domain_hosts[$domain]['filetype'])) {
                $this->m_ary_domain_hosts[$domain]['filetype'][] = $filetype;
                $this->m_ary_domain_hosts[$domain]['cnt_filetype'] += 1;
                $this->m_ary_domain_hosts[$domain]['urls'][] = $line;

                $max_hostpart = max(array_map('strlen', explode('.', $host)));
                $this->m_ary_domain_hosts[$domain]['percent_part_host'] = $max_hostpart  / strlen($host);
                $this->m_ary_domain_hosts[$domain]['percent_host_url'] = strlen($host)  / strlen($line);
            }

            if ($isip) {
                continue;
            }

            //deal with those urls that directly in or indirectly in Alexa
            $directInAlexa = $this->m_util->isDirectInAlexaTop($domain, $host);
            $inDirectInAlexa = $this->m_util->isInDirectInAlexaTop($domain, $host);
            if (!$directInAlexa and !$inDirectInAlexa) {
                continue;
            }

            $in = 'direct';
            if ($inDirectInAlexa) {
                $in = 'indirect';
            }

            if (!array_key_exists($host, $this->m_ary_inAlexa)) {
                $this->m_ary_inAlexa[$host] = array(
                                                    'domain' => $domain,
                                                    'inAlexa' => $in,
                                                    'urls' => array()); 
            }
            array_push($this->m_ary_inAlexa[$host]['urls'], $line);
        }

        foreach ($this->m_ary_domain_hosts as $domain => $hostInfo) {
            $uniq_hosts = array_unique($hostInfo['hosts']);
            $this->m_ary_domain_hosts[$domain]['hosts'] = $uniq_hosts;
            $this->m_ary_domain_hosts[$domain]['cnt_hosts'] = count($uniq_hosts);

            $this->m_ary_domain_hosts[$domain]['host_max_len'] = max(array_map('strlen', $uniq_hosts));
            $this->m_ary_domain_hosts[$domain]['host_min_len'] = min(array_map('strlen', $uniq_hosts));
        }
        
        foreach ($this->m_ary_inAlexa as $host => $hostInfo) {
            $uniq_urls = array_unique($hostInfo['urls']);
            $this->m_ary_inAlexa[$host]['urls'] = $uniq_urls;
        }

        return array($this->m_ary_domain_hosts, $this->m_ary_inAlexa);
    }   

    public function dumpStat_Domain_Hosts($filename)
    {
        self::doStat_Domain_Hosts($filename);

        URLChecker::arrayMultiSort($this->m_ary_domain_hosts, 'cnt_hosts', SORT_DESC);
        $fw_domain_hosts = fopen("{$filename}_domain_hosts.txt", "wb");
        foreach ($this->m_ary_domain_hosts as $domain => $hostInfo) {
            if ($hostInfo['isInAlexaTop']) {
                continue;
            }

            if ($hostInfo['isip']) {
                continue;
            }

            $valid = '';
            if (!$hostInfo['isvaliddomain']) {
                $valid = 'invalid';
            }
            
            $url_host = $hostInfo['cnt_hosts']  / $hostInfo['cnt_urls'];
            $max_min = $hostInfo['host_min_len'] / $hostInfo['host_max_len'];

            $infoAry = array($domain, $hostInfo['cnt_hosts'], $hostInfo['cnt_urls'], $url_host, 
                            $hostInfo['host_max_len'], $hostInfo['host_min_len'], $max_min, $hostInfo['sub_max_len'],
                            $hostInfo['percent_part_host'], $hostInfo['percent_host_url'],
                            $hostInfo['cnt_filetype'], $valid, '_domain_'); #implode("\t", $hostInfo['filetype'])); 
            if ($hostInfo['cnt_filetype'] < 10) {
                $infoAry[] = implode("\t", $hostInfo['filetype']); 
            }

            fwrite($fw_domain_hosts,  implode("\t", $infoAry) . "\n");
            foreach ($hostInfo['hosts'] as $host) {
                fwrite($fw_domain_hosts, "\t$host\n");
            }

            foreach ($hostInfo['urls'] as $url) {
                fwrite($fw_domain_hosts, "\t$url\n");
            }
        }
        fclose($fw_domain_hosts);

        $fw_direct = fopen("{$filename}_directinalexa.txt", "wb");
        $fw_indirect = fopen("{$filename}_indirectinalexa.txt", "wb");
        foreach ($this->m_ary_inAlexa as $host => $hostInfo) {
            $in = $hostInfo['inAlexa'];
            $fw = $fw_direct;
            if ($in == 'indirect') {
                $fw = $fw_indirect;
            }

            foreach ($hostInfo['urls'] as $url) {
                $infoAry = array($hostInfo['domain'], $host, $url);
                fwrite($fw, implode("\t", $infoAry) . "\n");
            }
        }
        fclose($fw_direct);
        fclose($fw_indirect);
    } 

    /*
    desc: array sort

    params: $oriArray is the original array to be sorted
            $key
            $order can be SORT_ASC, SORT_DESC
     */
    public static function arrayMultiSort(& $oriArray, $key, $order)
    {
        $tmpAry = array();

        foreach ($oriArray as $tmpKey => $row) {
            $tmpAry[$tmpKey]  = $row[$key];
        }

        array_multisort($tmpAry, $order, $oriArray);

        $tmpAry = null;
        unset($tmpAry);
    }

}

testEntry();

function testEntry()
{
    global $argv;
    $obj = new URLChecker();
    //var_dump($obj->getHostInfo($argv[1]));
    //var_dump(URLChecker::str_rpartition($argv[1], $argv[2]));
    $obj->dumpStat_Domain_Hosts($argv[1]);
    //$obj->dumpSimpleStat_Domain_Hosts($argv[1]);
    //$obj->dumpSuspiciousURL_Domain_Hosts($argv[1]);
}
