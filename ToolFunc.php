<?php

/* 全站公共方法
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * 生成六位的随机码
 * @param type $length
 * @return type
 */
function rand_code($length = 6)
{
    $chars = '123456789';
    for($i = 0, $count = strlen($chars); $i < $count; $i++){
        $arr[$i] = $chars[$i];
    }
    mt_srand((double)microtime() * 1000000);
    shuffle($arr);

    return substr(implode('', $arr), 3, $length);
}

/*
 * 获得客户端真实的IP地址 字符串形式
 */

function getIP()
{
    if (getenv("HTTP_CLIENT_IP") && strcasecmp(getenv("HTTP_CLIENT_IP"), "unknown")){
        $ip = getenv("HTTP_CLIENT_IP");
    }else{
        if (getenv("HTTP_X_FORWARDED_FOR") && strcasecmp(getenv("HTTP_X_FORWARDED_FOR"), "unknown")){
            $ip = getenv("HTTP_X_FORWARDED_FOR");
        }else{
            if (getenv("REMOTE_ADDR") && strcasecmp(getenv("REMOTE_ADDR"), "unknown")){
                $ip = getenv("REMOTE_ADDR");
            }else{
                if (isset($_SERVER ['REMOTE_ADDR']) && $_SERVER ['REMOTE_ADDR'] && strcasecmp($_SERVER ['REMOTE_ADDR'], "unknown")){
                    $ip = $_SERVER ['REMOTE_ADDR'];
                }else{
                    $ip = "unknown";
                }
            }
        }
    }

    return ($ip);
}

function getBrowser()
{
    $agent = $_SERVER["HTTP_USER_AGENT"];
    if (strpos($agent, 'MSIE') !== false || strpos($agent, 'rv:11.0')) //ie11判断
    {
        return "ie";
    }else{
        if (strpos($agent, 'Firefox') !== false){
            return "firefox";
        }else{
            if (strpos($agent, 'Chrome') !== false){
                return "chrome";
            }else{
                if (strpos($agent, 'Opera') !== false){
                    return 'opera';
                }else{
                    if ((strpos($agent, 'Chrome') == false) && strpos($agent, 'Safari') !== false){
                        return 'safari';
                    }else{
                        return 'unknown';
                    }
                }
            }
        }
    }
}

function getBrowserVer()
{
    if (empty($_SERVER['HTTP_USER_AGENT'])){    //当浏览器没有发送访问者的信息的时候
        return 'unknow';
    }
    $agent = $_SERVER['HTTP_USER_AGENT'];
    if (preg_match('/MSIE\s(\d+)\..*/i', $agent, $regs)){
        return $regs[1];
    }elseif (preg_match('/FireFox\/(\d+)\..*/i', $agent, $regs)){
        return $regs[1];
    }elseif (preg_match('/Opera[\s|\/](\d+)\..*/i', $agent, $regs)){
        return $regs[1];
    }elseif (preg_match('/Chrome\/(\d+)\..*/i', $agent, $regs)){
        return $regs[1];
    }elseif ((strpos($agent, 'Chrome') == false) && preg_match('/Safari\/(\d+)\..*$/i', $agent, $regs)){
        return $regs[1];
    }else{
        return 'unknow';
    }
}

/**
 * 检查名字
 * @param $str
 * @return bool
 */
function checkName($str, $min = 2, $max = 15)
{

    if (preg_match("/[\s\'.,_><:;*?~`!@#$%^&+=)(<>{}]|\]|\[|\/|\\\|\"|\|/", $str)){ //不允许特殊字符
        return false;
    }
    if (!preg_match('/^[\x{4e00}-\x{9fa5}]+$/u', $str)){
        return false;
    };
    if (mb_strlen($str, "utf-8") < $min || mb_strlen($str, "utf-8") > $max){
        return false;
    }

    return true;
}

/**
 * 检查字符特殊字符
 * @param $str
 * @return bool
 */
function checkStr($str, $min = 2, $max = 20)
{

    if (preg_match("/[\s\'_><.,:;*?~`!@#$%^&+=)(<>{}]|\]|\[|\/|\\\|\"|\|/", $str)){ //不允许特殊字符
        return false;
    }

    if (mb_strlen($str, "utf-8") < $min || mb_strlen($str, "utf-8") > $max){
        return false;
    }

    return true;
}

/**
 * 检查字符特殊字符
 * @param $str
 * @return bool
 */
function checkJob($str, $min = 2, $max = 20)
{

    if (preg_match("/[\s\',><:;*?~`!@#$%^&+=<>{}]|\]|\[|\|\"|\|/", $str)){ //不允许特殊字符
        return false;
    }
    if (mb_strlen($str, "utf-8") < $min || mb_strlen($str, "utf-8") > $max){
        return false;
    }

    return true;
}

/**
 *  电话号码验证
 *
 * @author abc
 */
function verify_phone($phone)
{
    if (preg_match('/^(1(([3|5|7][0-9])|(47)|[68][0123456789]))\d{8}$/', $phone)){
        return true;
    }else{
        return false;
    }
}

/**
 * 验证用户名
 * @param type $username
 * @return boolean
 */
function verify_name($username)
{
    if (preg_match('/^[a-zA-Z0-9]{4,15}?$/', $username)){
        return true;
    }else{
        return false;
    }
}

/**
 * 身份证隐藏
 * @param type $card
 * @return type
 */
function hidCard4($card)
{
    $card = aes($card, 'DECODE');
    $offset = strlen($card) - 4;

    return preg_replace("/(\d{{$offset}})(\w+)/", "****$2", $card);
}

/**
 * 验证身份证号码。
 * @param type $cardno
 * @return boolean
 */
function isCardNo($cardno)
{
    if (strlen($cardno) != 18){
        return false;
    }
    $IDCardBody = substr($cardno, 0, 17); //身份证主体
    $IDCardCode = strtoupper(substr($cardno, 17, 1)); //身份证最后一位的验证码
    if (strlen($IDCardBody) != 17){
        return false;
    }
    //加权因子
    $factor = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    //校验码对应值
    $code = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
    $checksum = 0;
    for($i = 0; $i < strlen($IDCardBody); $i++){
        $checksum += substr($IDCardBody, $i, 1) * $factor[$i];
    }
    $chkIDCardCode = $code[$checksum % 11];
    if ($chkIDCardCode != $IDCardCode){
        return false;
    }else{
        return true;
    }
}

/**
 * email邮箱验证
 * @param type $email
 * @return boolean
 */
function verify_email($email)
{
    if (!empty($email) && preg_match("/^[0-9a-zA-Z]+@(([0-9a-zA-Z]+)[.])+[a-z]{2,4}$/i", $email)){
        return true;
    }

    return false;
}

/**
 * 身份证隐藏
 * @param type $card
 * @return type
 */
function hidCard8($card)
{
    $card = aes($card, 'DECODE');
    $offset = strlen($card) - 8;

    return preg_replace("/(\d{4})(\d{{$offset}})(\w+)/", "$1" . str_repeat("*", $offset) . "$3", $card);
}

/**
 * 银行卡隐藏
 * @param type $card
 * @return type
 */
function hidBankCard($card)
{
    $offset = strlen($card) - 8;

    return preg_replace("/(\d{4})(\d{{$offset}})(\w+)/", "$1" . str_repeat("*", $offset) . "$3", $card);
}

/**
 * 隐藏电话号码
 * @param type $phone
 * @return type
 */
function hidPhone($phone)
{
    return preg_replace("/(\d{3})(\d{4})(\d{4})/", "$1****$3", $phone);
}

/**
 * 隐藏姓名
 * @param type $name
 * @return string
 */
function hidRealName($name)
{
    $name = aes($name, 'DECODE');
    $str = "";
    preg_match_all("/(\S)/u", $name, $str);

    return $str[1][0] . str_repeat("*", count($str[1]) - 1);
}

/**
 * 用户名隐藏
 * @param type $name
 * @return type
 */
function hidUserName($name)
{
    $str = "";
    preg_match_all("/(\S)/u", $name, $str);

    return $str[1][0] . str_repeat("*", 3) . $str[1][count($str[1]) - 1];
}

/**
 * 融资标链接
 * @param type $bno
 * @param type $str
 * @return string
 */
function borrowLink($bno, $str)
{
    //$result = "[&" . $bno . "' #" . $str . "@]";
    $result = " <a href='{0}" . $bno . "' target='_blank'>$str</a>";

    return $result;
}

/**
 * 有小数显示，无小数不显示
 * Enter description here ...
 * @param $money
 */
function subOnlyMoney($money)
{
    return floatval($money);
}

/**
 * 金额处理，不进入四舍五入，保留两位小数，不进行格式化
 * @param type $money
 * @return type
 */
function pointMoney($money)
{
    return sprintf("%.2f", substr(sprintf("%.3f", $money), 0, -1));
}

/**
 * 金额截取，取整数
 * @param type $money
 * @return type
 */
function intMoney($money)
{
    if (strrpos($money, '.')){
        return substr($money, 0, strrpos($money, '.'));
    }else{
        return $money;
    }
}

/**
 * 金额格式化，不保留小数
 * @param type $money
 * @return type
 */
function subFormat($money)
{
    return number_format($money, 0);
}

/**
 * 四舍五入 保留两位小数
 * @param type $money
 * @return type
 */
function roundMoney($money)
{
    return round($money, 2);
}

/**
 * 四舍五入 保留两位小数 格式化金额
 * Enter description here ...
 * @param $money
 */
function formatMoney($money)
{
    return number_format(roundMoney($money), 2);
}

/**
 * 日期格式化
 * @param type $date
 */
function formatlongDate($date)
{
    if ($date){
        return date("Y-m-d H:i:s", $date);
    }

    return null;
}

/**
 * 日期格式化
 * @param type $date
 */
function formatshortDate($date)
{
    if ($date){
        return date("Y-m-d", $date);
    }

    return null;
}

/**
 * 日期格式化
 * @param type $date
 */
function formatTime($date)
{
    if ($date){
        return date("m-d H:i:s", $date);
    }

    return null;
}

/**
 * 性别
 * @param type $sex
 * @return string
 */
function formatSex($sex)
{
    $var = "";
    switch($sex){
        case "1":
            $var = "男";
            break;
        case "2":
            $var = "女";
            break;
        default:
            $var = "未知";
            break;
    }

    return $var;
}

/**
 * 格式化终端
 * @param type $param
 * @return string
 */
function formatterminal($param)
{
    $var = "";
    switch($param){
        case "1":
            $var = "PC";
            break;
        case "2":
            $var = "安卓";
            break;
        case "3":
            $var = "IOS";
            break;
        case "4":
            $var = "微信";
            break;
        case "5":
            $var = "自动";
            break;
        default:
            $var = "未知";
            break;
    }

    return $var;
}

/**
 * 检测验证码
 * @param integer $id 验证码ID
 * @return boolean 检测结果
 */
function checkverify($code, $id = '')
{
    $verify = new \Think\Verify ();

    return $verify->check($code, $id);
}

function curPageURL()
{
    $pageURL = 'http';
    $port = '80';
    if ($_SERVER["HTTPS"] == "on"){
        $pageURL .= "s";
        $port = '443';
    }
    $pageURL .= "://";
    if ($_SERVER["SERVER_PORT"] != $port){
        $pageURL .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
    }else{
        $pageURL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
    }

    return $pageURL;
}

/**
 * 生成随机密码
 * @param type $length
 * @return string
 */
function randomkeys($length)
{
    $returnStr = '';
    $pattern = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLOMNOPQRSTUVWXYZ';
    for($i = 0; $i < $length - 2; $i++){
        $returnStr .= $pattern{mt_rand(0, 61)};
    }

    $returnStr = $returnStr . rand(0, 9);
    $returnStr = $returnStr . chr(rand(97, 122));

    return $returnStr;
}

/**
 * 随机生成汉字
 * @param type $num
 * @return type
 */
function getChar($num = 4)
{
    $b = '';
    for($i = 0; $i < $num; $i++){
        // 使用chr()函数拼接双字节汉字，前一个chr()为高位字节，后一个为低位字节
        $a = chr(mt_rand(0xB0, 0xD0)) . chr(mt_rand(0xA1, 0xF0));
        // 转码
        $b .= iconv('GB2312', 'UTF-8', $a);
    }

    return $b;
}

/**
 * 安全过滤类-过滤HTML标签
 * @param string $value 需要过滤的值
 * @return string
 */
function fliter_html($value)
{
    if (function_exists('htmlspecialchars')){
        return htmlspecialchars($value);
    }

    return str_replace(["&", '"', "'", "<", ">"], ["&", "\"", "'", "<", ">"], $value);
}

/**
 * 安全过滤类-字符串过滤 过滤特殊有危害字符
 * @param string $value 需要过滤的值
 * @return string
 */
function fliter_str($value)
{
    $badstr = ["\0", "%00", "\r", '&', ' ', '"', "'", "<", ">", "   ", "%3C", "%3E"];
    $newstr = ['', '', '', '&', ' ', '', "<", ">", "   ", "<", ">"];
    $value = str_replace($badstr, $newstr, $value);
    $value = preg_replace('/&((#(\d{3,5}|x[a-fA-F0-9]{4}));)/', '&\\1', $value);

    return $value;
}

/**
 * 安全过滤类-过滤javascript,css,iframes,object等不安全参数 过滤级别高
 * @param string $value 需要过滤的值
 * @return string
 */
function fliter_script($value)
{
    $value = preg_replace("/(javascript:)?on(click|load|key|mouse|error|abort|move|unload|change|dblclick|move|reset|resize|submit)|document\./i", "&111n\\2", $value);
    $value = preg_replace("/(.*?)<\/script>/si", "", $value);
    $value = preg_replace("/(.*?)<\/iframe>/si", "", $value);
    $value = preg_replace("//iesU", '', $value);

    return $value;
}

/**
 * 安全过滤类-字符串过滤 过滤特殊有危害字符 微信特殊对待
 * @param string $value 需要过滤的值 【%00 ：url终止符】
 * @return string
 */
function wx_fliter_str($value)
{
    $badstr = ["\0", "%00", "\r", "'", "<", ">",];
    $newstr = ['', '', '', '', '', "",];
    $value = str_replace($badstr, $newstr, $value);
    $value = preg_replace('/&((#(\d{3,5}|x[a-fA-F0-9]{4}));)/', '&\\1', $value);

    return $value;
}

/**
 * +----------------------------------------------------------
 * 将一个字符串部分字符用*替代隐藏
 * +----------------------------------------------------------
 * @param string $string 待转换的字符串
 * @param int $bengin 起始位置，从0开始计数，当$type=4时，表示左侧保留长度
 * @param int $len 需要转换成*的字符个数，当$type=4时，表示右侧保留长度
 * @param int $type 转换类型：0，从左向右隐藏；1，从右向左隐藏；2，从指定字符位置分割前由右向左隐藏；3，从指定字符位置分割后由左向右隐藏；4，保留首末指定字符串
 * @param string $glue 分割符
 * +----------------------------------------------------------
 * @return string   处理后的字符串
 * +----------------------------------------------------------
 */
function hideStr($string, $bengin = 0, $len = 4, $type = 0, $glue = "@")
{
    if (empty($string)){
        return false;
    }
    $array = [];
    if ($type == 0 || $type == 1 || $type == 4){
        $strlen = $length = mb_strlen($string);
        while($strlen){
            $array[] = mb_substr($string, 0, 1, "utf8");
            $string = mb_substr($string, 1, $strlen, "utf8");
            $strlen = mb_strlen($string);
        }
    }
    if ($type == 0){
        for($i = $bengin; $i < ($bengin + $len); $i++){
            if (isset($array[$i])){
                $array[$i] = "**";
            }
        }
        $string = implode("", $array);
    }else{
        if ($type == 1){
            $array = array_reverse($array);
            for($i = $bengin; $i < ($bengin + $len); $i++){
                if (isset($array[$i])){
                    $array[$i] = "**";
                }
            }
            $string = implode("", array_reverse($array));
        }else{
            if ($type == 2){
                $array = explode($glue, $string);
                $array[0] = hideStr($array[0], $bengin, $len, 1);
                $string = implode($glue, $array);
            }else{
                if ($type == 3){
                    $array = explode($glue, $string);
                    $array[1] = hideStr($array[1], $bengin, $len, 0);
                    $string = implode($glue, $array);
                }else{
                    if ($type == 4){
                        $left = $bengin;
                        $right = $len;
                        $tem = [];
                        for($i = 0; $i < ($length - $right); $i++){
                            if (isset($array[$i])){
                                $tem[] = $i >= $left ? "**" : $array[$i];
                            }
                        }
                        $array = array_chunk(array_reverse($array), $right);
                        $array = array_reverse($array[0]);
                        for($i = 0; $i < $right; $i++){
                            $tem[] = $array[$i];
                        }
                        $string = implode("", $tem);
                    }
                }
            }
        }
    }

    return $string;
}

/**
 * 支持utf8中文字符截取
 * @param string $text 待处理字符串
 * @param int $start 从第几位截断
 * @param int $sublen 截断几个字符
 * @param string $ellipsis 附加省略字符
 * @param string $code 字符串编码
 * @return    string
 */
function sub_str($string, $start = 0, $sublen = 12, $ellipsis = '', $code = 'UTF-8')
{
    if ($code == 'UTF-8'){
        $pa = "/[\x01-\x7f]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xef][\x80-\xbf][\x80-\xbf]|\xf0[\x90-\xbf][\x80-\xbf][\x80-\xbf]|[\xf1-\xf7][\x80-\xbf][\x80-\xbf][\x80-\xbf]/";
        preg_match_all($pa, $string, $t_string);
        $intTemp = 0;
        foreach($t_string[0] as $k => $v){
            if (strpos("~!@#$%^&*()_+{}|\":<>?`1234567890-=[]\;',./abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ", $v) !== false && $k <= $sublen){
                $intTemp++;
            };
        }
        $sublen = $sublen + floor($intTemp / 2);
        if (count($t_string[0]) - $start > $sublen){
            return join('', array_slice($t_string[0], $start, $sublen)) . $ellipsis;
        }

        return join('', array_slice($t_string[0], $start, $sublen));
    }else{
        $start = $start;
        $strlen = strlen($string);
        if ($sublen != 0){
            $sublen = $sublen * 2;
        }else{
            $sublen = $strlen;
        }
        $tmpstr = '';
        for($i = 0; $i < $strlen; $i++){
            if ($i >= $start && $i < ($start + $sublen)){
                if (ord(substr($string, $i, 1)) > 129){
                    $tmpstr .= substr($string, $i, 2);
                }else{
                    $tmpstr .= substr($string, $i, 1);
                }
            }
            if (ord(substr($string, $i, 1)) > 129){
                $i++;
            }
        }
        if (strlen($tmpstr) < $strlen){
            $tmpstr .= $ellipsis;
        }

        return $tmpstr;
    }
}

/**
 * 编辑器过滤字符串
 * @param type $str
 * @return string
 */
function filter_UEditor($text)
{
    $text = trim($text);
    $text = stripslashes($text);
    //完全过滤注释
    $text = preg_replace('/<!--?.*-->/', '', $text);
    //完全过滤动态代码
    $text = preg_replace('/<\?|\?>/', '', $text);
    //完全过滤js
    $text = preg_replace('/<script?.*\/script>/', '', $text);
    $text = str_replace('[', '&#091;', $text);
    $text = str_replace(']', '&#093;', $text);
    $text = str_replace('|', '&#124;', $text);
    //过滤换行符
    $text = preg_replace('/\r?\n/', '', $text);
    //br
    $text = preg_replace('/<br(\s\/)?>/i', '[br]', $text);
    $text = preg_replace('/(\[br\]\s*){10,}/i', '[br]', $text);
    //hr img area input
    $text = preg_replace('/<(hr|img|input|area|isindex)( [^><\[\]]*)>/i', '[\1\2]', $text);
    //过滤多余html
    $text = preg_replace('/<\/?(html|head|meta|link|base|body|title|style|script|form|iframe|frame|frameset)[^><]*>/i', '', $text);
    //过滤on事件lang js
    while(preg_match('/(<[^><]+)( lang|onfinish|onmouse|onexit|onerror|onclick|onkey|onload|onchange|onfocus|onblur)[^><]+/i', $text, $mat)){
        $text = str_replace($mat[0], $mat[1], $text);
    }
    while(preg_match('/(<[^><]+)(window\.|javascript:|js:|about:|file:|document\.|vbs:|cookie)([^><]*)/i', $text, $mat)){
        $text = str_replace($mat[0], $mat[1] . $mat[3], $text);
    }
    //过滤合法的html标签
    while(preg_match('/<([a-z]+)[^><\[\]]*>[^><]*<\/\1>/i', $text, $mat)){
        $text = str_replace($mat[0], str_replace('>', ']', str_replace('<', '[', $mat[0])), $text);
    }
    //转换引号
    while(preg_match('/(\[[^\[\]]*=\s*)(\"|\')([^\2=\[\]]+)\2([^\[\]]*\])/i', $text, $mat)){
        $text = str_replace($mat[0], $mat[1] . '|' . $mat[3] . '|' . $mat[4], $text);
    }
    //过滤错误的单个引号
    while(preg_match('/\[[^\[\]]*(\"|\')[^\[\]]*\]/i', $text, $mat)){
        $text = str_replace($mat[0], str_replace($mat[1], '', $mat[0]), $text);
    }
    //转换其它所有不合法的 < >
    $text = str_replace('<', '&lt;', $text);
    $text = str_replace('>', '&gt;', $text);
    $text = str_replace('"', '&quot;', $text);
    //反转换
    $text = str_replace('[', '<', $text);
    $text = str_replace(']', '>', $text);
    $text = str_replace('|', '"', $text);
    //过滤多余空格
    $text = str_replace(' ', ' ', $text);

    return $text;
}

/**
 *  简单加密
 * @param type $string
 * @param type $key
 * @return type
 */
function authSimpleSK($tex, $key, $type = "encode")
{
    $chrArr = [
        'a',
        'b',
        'c',
        'd',
        'e',
        'f',
        'g',
        'h',
        'i',
        'j',
        'k',
        'l',
        'm',
        'n',
        'o',
        'p',
        'q',
        'r',
        's',
        't',
        'u',
        'v',
        'w',
        'x',
        'y',
        'z',
        'A',
        'B',
        'C',
        'D',
        'E',
        'F',
        'G',
        'H',
        'I',
        'J',
        'K',
        'L',
        'M',
        'N',
        'O',
        'P',
        'Q',
        'R',
        'S',
        'T',
        'U',
        'V',
        'W',
        'X',
        'Y',
        'Z',
        '0',
        '1',
        '2',
        '3',
        '4',
        '5',
        '6',
        '7',
        '8',
        '9'
    ];
    if ($type == "DECODE"){
        if (strlen($tex) < 14){
            return false;
        }
        $verity_str = substr($tex, 0, 8);
        $tex = substr($tex, 8);
        if ($verity_str != substr(md5($tex), 0, 8)){
            //完整性验证失败
            return false;
        }
    }
    $key_b = $type == "DECODE" ? substr($tex, 0, 6)
        : $chrArr[rand() % 62] . $chrArr[rand() % 62] . $chrArr[rand() % 62] . $chrArr[rand() % 62] . $chrArr[rand() % 62] . $chrArr[rand() % 62];
    $rand_key = $key_b . $key;
    $rand_key = md5($rand_key);
    $tex = $type == "DECODE" ? base64_decode(substr($tex, 6)) : $tex;
    $texlen = strlen($tex);
    $reslutstr = "";
    for($i = 0; $i < $texlen; $i++){
        $reslutstr .= $tex{$i} ^ $rand_key{$i % 32};
    }
    if ($type != "DECODE"){
        $reslutstr = trim($key_b . base64_encode($reslutstr), "==");
        $reslutstr = substr(md5($reslutstr), 0, 8) . $reslutstr;
    }

    return $reslutstr;
}

/**
 * 加密和解密有特殊字符的问题
 * @param type $string
 * @param type $operation
 * @param type $key
 * @param type $expiry
 * @return string
 */
function authSK($string, $operation = 'DECODE', $key = '', $expiry = 0)
{
    $ckey_length = 4;

    $key = md5($key ? $key : UC_KEY);
    $keya = md5(substr($key, 0, 16));
    $keyb = md5(substr($key, 16, 16));
    $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length) : substr(md5(microtime()), -$ckey_length)) : '';

    $cryptkey = $keya . md5($keya . $keyc);
    $key_length = strlen($cryptkey);

    $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length))
        : sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
    $string_length = strlen($string);

    $result = '';
    $box = range(0, 255);

    $rndkey = [];
    for($i = 0; $i <= 255; $i++){
        $rndkey[$i] = ord($cryptkey[$i % $key_length]);
    }

    for($j = $i = 0; $i < 256; $i++){
        $j = ($j + $box[$i] + $rndkey[$i]) % 256;
        $tmp = $box[$i];
        $box[$i] = $box[$j];
        $box[$j] = $tmp;
    }

    for($a = $j = $i = 0; $i < $string_length; $i++){
        $a = ($a + 1) % 256;
        $j = ($j + $box[$a]) % 256;
        $tmp = $box[$a];
        $box[$a] = $box[$j];
        $box[$j] = $tmp;
        $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
    }

    if ($operation == 'DECODE'){
        if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)){
            return substr($result, 26);
        }else{
            return '';
        }
    }else{
        return $keyc . str_replace('=', '', base64_encode($result));
    }
}


/**
 * 根据身份证获取年龄
 * @param type $card
 * @return type
 */
function getCardAge($card)
{
    if (strlen($card) < 10){
        return false;
    }
    $sub_str = substr($card, 6, 4);
    $now = date("Y", time());

    return $now - $sub_str;
}

/**
 * 获取性别
 * @param type $card
 */
function getSex($card)
{
    $var = substr($card, 16, 1);

    return $var % 2 ? 1 : 2;
}

/**
 * 根据身份证获取生日
 * @param type $card
 * @return type
 */
function getCardBirthday($card)
{
    $sub_str = substr($card, 10, 4);

    return $sub_str;
}

/**
 * 根据身份证获取生日
 * @param type $card
 * @return type
 */
function getCardBirthYear($card)
{
    $sub_str = substr($card, 6, 4);

    return $sub_str;
}

/**
 * 写入日志
 * @param type $mark
 * @param type $log_content
 */
function logger($mark, $log_content)
{
    $max_size = 100000;
    $log_filename = 'logs/' . date('Y-m-d') . "log.txt";
    if (file_exists($log_filename) && (abs(filesize($log_filename)) > $max_size)){
        unlink($log_filename);
    }
    file_put_contents($log_filename, date('Y-m-d H:i:s') . " 关键索引：" . $mark . "  内容：" . $log_content . "\r\n", FILE_APPEND);
}


/**
 *
 * 日志记录
 * @param type $log_content
 * @param type $dir request | response | error 目录
 * @param type $fileName 文件名字
 * @param type $item
 */
function logger_wge($log_content, $dir = 'request', $fileName = "other", $item = "Wge")
{

    $max_size = 100000000;

    $log_filename = 'logs/' . $item . '/' . date('Y-m-d') . "/" . $dir . "/" . $fileName . ".txt";
    // 自动创建日志目录
    $log_dir = dirname($log_filename);
    if (!is_dir($log_dir)){
        mkdir($log_dir, 0755, true);
    }
    if (file_exists($log_filename) && (abs(filesize($log_filename)) > $max_size)){
        unlink($log_filename);
    }
    file_put_contents($log_filename, date('Y-m-d H:i:s') . "    info ： " . $log_content . "\r\n", FILE_APPEND);
}

/**
 *
 * 日志记录
 * @param type $log_content
 * @param type $dir request | response | error 目录
 * @param type $fileName 文件名字
 * @param type $item
 */
function logger_api($mark, $log_content, $dir = "api")
{
    $max_size = 100000000;
    $log_filename = 'logs/' . $dir . '/' . date('Y-m-d') . ".txt";
    // 自动创建日志目录
    $log_dir = dirname($log_filename);
    if (!is_dir($log_dir)){
        mkdir($log_dir, 0755, true);
    }
    if (file_exists($log_filename) && (abs(filesize($log_filename)) > $max_size)){
        unlink($log_filename);
    }
    file_put_contents($log_filename, date('Y-m-d H:i:s') . " 关键索引：" . $mark . "  内容：" . $log_content . "\r\n", FILE_APPEND);
}

/**
 * 轮询任务日志
 * @param type $mark
 * @param type $log_content
 * @param type $type
 */
function logger_task($mark, $log_content, $type = '')
{
    $fileName = 'task.txt';
    if (!empty($type)){
        $fileName = $type . '.txt';
    }
    $max_size = 100000000;
    $logpath = 'logs/Task/';
    if (defined('TASKLOG_PATH')){
        $logpath = TASKLOG_PATH;
        echo 333;
    }
    $log_filename = $logpath . date('Y-m-d') . "/" . $fileName;
    // 自动创建日志目录
    $log_dir = dirname($log_filename);
    if (!is_dir($log_dir)){
        mkdir($log_dir, 0755, true);
    }
    //检测日志文件大小，超过配置大小则备份日志文件重新生成
    if (is_file($log_filename) && floor($max_size) <= filesize($log_filename)){
        rename($log_filename, dirname($log_filename) . '/' . time() . '-' . basename($log_filename));
    }
    file_put_contents($log_filename, date('Y-m-d H:i:s') . " 关键索引：" . $mark . "  内容：" . $log_content . "\r\n", FILE_APPEND);
}

/**
 * 二维码日志
 * @param type $mark
 * @param type $log_content
 * @param type $dir
 */
function logger_rqcode($mark, $log_content, $dir = "rqcode")
{
    $max_size = 100000000;
    $log_filename = 'logs/' . $dir . '/' . date('Y-m-d') . ".txt";
    // 自动创建日志目录
    $log_dir = dirname($log_filename);
    if (!is_dir($log_dir)){
        mkdir($log_dir, 0755, true);
    }
    if (file_exists($log_filename) && (abs(filesize($log_filename)) > $max_size)){
        unlink($log_filename);
    }
    file_put_contents($log_filename, date('Y-m-d H:i:s') . " 关键索引：" . $mark . "  内容：" . $log_content . "\r\n", FILE_APPEND);
}


/**
 *
 * @param type $url 传递链融资链接地址 格式为{0}xxxxxxxxxx
 * @param type $pc_or_wx [ PC:1 , 微信 : 2 ]
 * @param type $type [获取完整<a>标签地址</a> : 1 ， 获取url地址 : 2 ]
 * @return string 返回地址 或者 <a>标签
 */
function borrowLinkFormat($url, $pc_or_wx = 1, $type = 1)
{
    $ret_url = "";
    $pc_url = "/Project/invest/detail/";
    $wx_url = "/Wechat/Project/detail/borrowNO/";
    $replace_url = ($pc_or_wx == 1) ? $pc_url : $wx_url;

    if ($type == 1){
        $ret_url = str_replace("{0}", $replace_url, $url);
    }else{
        preg_match_all('/href=[\'"](.*[0-9])[\'"]/', $url, $match);
        if (!empty($match[1])){
            $ret_url = str_replace("{0}", $replace_url, $match[1][0]);
        }
    }

    return $ret_url;
}

/**
 * 进度条处理
 * @param type $point
 */
function speedForamt($point)
{
    if ($point > 0 && $point < 1){
        $point = 1;
    }else{
        $point = floor($point);
    }

    return $point;
}

/**
 * 根据具体值获取相应的时间戳--向前
 * @param type $type
 * @return type
 */
function getDateToMic($type = "week")
{
    $limit = [];
    switch($type){
        case "week":
            $limit["start"] = strtotime(date("Y-m-d H:i:s", mktime(0, 0, 0, date("m"), date("d") - 6, date("Y"))));
            $limit["end"] = strtotime(date("Y-m-d H:i:s", mktime(23, 59, 59, date("m"), date("d"), date("Y"))));

            return $limit;
        case "month":
            $limit["start"] = strtotime(date("Y-m-d H:i:s", mktime(0, 0, 0, date("m") - 1, date("d"), date("Y"))));
            $limit["end"] = strtotime(date("Y-m-d H:i:s", mktime(23, 59, 59, date("m"), date("d"), date("Y"))));

            return $limit;
        case "2month":
            $limit["start"] = strtotime(date("Y-m-d H:i:s", mktime(0, 0, 0, date("m") - 2, date("d"), date("Y"))));
            $limit["end"] = strtotime(date("Y-m-d H:i:s", mktime(23, 59, 59, date("m"), date("d"), date("Y"))));

            return $limit;
        case "3month":
            $limit["start"] = strtotime(date("Y-m-d H:i:s", mktime(0, 0, 0, date("m") - 3, date("d"), date("Y"))));
            $limit["end"] = strtotime(date("Y-m-d H:i:s", mktime(23, 59, 59, date("m"), date("d"), date("Y"))));

            return $limit;
    }

    return $limit;
}

/** 向后
 * 日期的时间间隔
 * @param type $type
 * @return type
 */
function getDateToAfter($type = "week")
{
    $limit = [];
    switch($type){
        case "week":
            $limit["start"] = strtotime(date("Y-m-d H:i:s", mktime(0, 0, 0, date("m"), date("d"), date("Y"))));
            $limit["end"] = strtotime(date("Y-m-d H:i:s", mktime(23, 59, 59, date("m"), date("d") + 6, date("Y"))));

            return $limit;
        case "month":
            $limit["start"] = strtotime(date("Y-m-d H:i:s", mktime(0, 0, 0, date("m"), date("d"), date("Y"))));
            $limit["end"] = strtotime(date("Y-m-d H:i:s", mktime(23, 59, 59, date("m") + 1, date("d"), date("Y"))));

            return $limit;
        case "2month":
            $limit["start"] = strtotime(date("Y-m-d H:i:s", mktime(0, 0, 0, date("m"), date("d"), date("Y"))));
            $limit["end"] = strtotime(date("Y-m-d H:i:s", mktime(23, 59, 59, date("m") + 2, date("d"), date("Y"))));

            return $limit;
        case "3month":
            $limit["start"] = strtotime(date("Y-m-d H:i:s", mktime(0, 0, 0, date("m"), date("d"), date("Y"))));
            $limit["end"] = strtotime(date("Y-m-d H:i:s", mktime(23, 59, 59, date("m") + 3, date("d"), date("Y"))));

            return $limit;
    }

    return $limit;
}

/**
 * 创建GUID
 * @param type $prefix
 * @return type
 */
function create_uuid($prefix = "")
{    //可以指定前缀
    $str = md5(uniqid(mt_rand(), true));
    $uuid = substr($str, 0, 8) . '-';
    $uuid .= substr($str, 8, 4) . '-';
    $uuid .= substr($str, 12, 4) . '-';
    $uuid .= substr($str, 16, 4) . '-';
    $uuid .= substr($str, 20, 12);

    return $prefix . $uuid;
}

/**
 * 如果是空数组返回空字符串。
 * @param type $arr
 */
function emptyArrToStr($arr)
{
    if (is_array($arr) && count($arr) == 0){
        return "";
    }

    return $arr;
}

/**
 * 返回结果。
 * @param type $status 状态。
 * @param type $msg 结果消息。
 * @param type $data 结果数据。
 */
function backToResults($status = 0, $msg = '', $data = null)
{
    return ['status' => $status, 'msg' => $msg, 'data' => $data];
}

/**
 * 加密
 * @param type $string
 * @param type $skey
 * @return type
 */
function encrypt($string = '', $skey = 'qianhezi20150826')
{
    $strArr = str_split(base64_encode($string));
    $strCount = count($strArr);
    foreach(str_split($skey) as $key => $value)
        $key < $strCount && $strArr[$key] .= $value;

    return str_replace(['=', '+', '/'], ['O0O0O', 'o000o', 'oo00o'], join('', $strArr));
}

/**
 * 解密
 * @param type $string
 * @param type $skey
 * @return type
 */
function decrypt($string = '', $skey = 'qianhezi20150826')
{
    $strArr = str_split(str_replace(['O0O0O', 'o000o', 'oo00o'], ['=', '+', '/'], $string), 2);
    $strCount = count($strArr);
    foreach(str_split($skey) as $key => $value)
        $key <= $strCount && $strArr[$key][1] === $value && $strArr[$key] = $strArr[$key][0];

    return base64_decode(join('', $strArr));
}

/**
 * 文件流留生成zip
 * @param type $baseData
 * @param type $dir 目录 例如": "/a/b/c"
 * @param type $fileName
 * @return string
 */
function base64DecZip($baseData, $dir, $fileName)
{
    $__root__ = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : (isset($_SERVER['APPL_PHYSICAL_PATH']) ? trim($_SERVER['APPL_PHYSICAL_PATH'], "\\") : (isset($_['PATH_TRANSLATED']) ? str_replace($_SERVER["PHP_SELF"]) : str_replace(str_replace("/", "\\", isset($_SERVER["PHP_SELF"]) ? $_SERVER["PHP_SELF"] : (isset($_SERVER["URL"]) ? $_SERVER["URL"] : $_SERVER["SCRIPT_NAME"])), "", isset($_SERVER["PATH_TRANSLATED"]) ? $_SERVER["PATH_TRANSLATED"] : $_SERVER["SCRIPT_FILENAME"])));
    $storageDir = $__root__ . $dir . date("Y-m-d") . "/";
    if (!file_exists($storageDir)){
        mkdir($storageDir, 0777, true);
    }
    $storageDir = $storageDir . $fileName . '.zip';
    $export = base64_decode(str_replace("data:text/plain;base64,", '', $baseData));
    file_put_contents($storageDir, $export);

    return $storageDir;
}

/**
 * 生成压缩文件
 * @param type $zipPath /a/b/c.zip   生成的zip路径
 * @param type $filePath /a/b/d.txt  提供压缩文件
 * @param type $fileName /b/d.txt   压缩文件中层级目录
 */
function fileZip($zipPath, $filePath, $fileName)
{

    if (!file_exists($filePath) || empty($filePath) || empty($fileName)){
        return false;
    }
    $zip = new ZipArchive();
    $res = $zip->open($zipPath, ZipArchive::CREATE);
    if ($res === true){
        $zip->addFile($filePath, $fileName);
        $zip->close();
    }

    return true;
}

/**
 * 检测客户端是否为手机浏览器。
 * @return boolean
 */
function isMobile()
{
    // 如果有HTTP_X_WAP_PROFILE则一定是移动设备
    if (isset($_SERVER['HTTP_X_WAP_PROFILE'])){
        return true;
    }
    // 如果via信息含有wap则一定是移动设备,部分服务商会屏蔽该信息
    if (isset($_SERVER['HTTP_VIA'])){
        // 找不到为flase,否则为true
        return stristr($_SERVER['HTTP_VIA'], "wap") ? true : false;
    }
    $mobile = [];
    static $mobilebrowser_list = 'Mobile|iPhone|Android|WAP|NetFront|JAVA|OperasMini|UCWEB|WindowssCE|Symbian|Series|webOS|SonyEricsson|Sony|BlackBerry|Cellphone|dopod|Nokia|samsung|PalmSource|Xphone|Xda|Smartphone|PIEPlus|MEIZU|MIDP|CLDC';
    //note 获取手机浏览器
    if (preg_match("/$mobilebrowser_list/i", $_SERVER['HTTP_USER_AGENT'], $mobile)){
        return true;
    }else{
        if (preg_match('/(mozilla|chrome|safari|opera|m3gate|winwap|openwave)/i', $_SERVER['HTTP_USER_AGENT'])){
            return false;
        }else{
            if ($_GET['mobile'] === 'yes'){
                return true;
            }else{
                return false;
            }
        }
    }
}

/**
 * 判断是否是在微信浏览器里
 * @param type $from
 */
function isWeixinBrowser()
{
    $agent = $_SERVER ['HTTP_USER_AGENT'];
    if (!strpos($agent, "icroMessenger")){
        return false;
    }

    return true;
}

/**
 * 判断是否是在启脉APP里
 * @param type $from
 */
function isApp()
{
    if (preg_match('/(Qianhezi|qianhezi|qhz)/i', $_SERVER['HTTP_USER_AGENT'])){
        return true;
    }

    return false;
}

/**
 * 验证密码组合
 * @param type $candidate
 * @return string|boolean
 *
 */
function valid_pass($candidate)
{
    $r1 = '/[A-Za-z]/';  //uppercase
    $r3 = '/[0-9]/';  //numbers
    $r4 = '/[~!@#$%^&*()\-_=+{};:<,.>?\'"\/]/';  // special char
    $i = 0;
    if (preg_match_all($r1, $candidate, $o) < 1){
        $i++;
    }
    if (preg_match_all($r3, $candidate, $o) < 1){
        $i++;
    }
    if (preg_match_all($r4, $candidate, $o) < 1){
        $i++;
    }
    if ($i > 1){
        return "密码组合至少包含数字，字母或者特殊字符任意两种!";
    }
    if (strlen($candidate) < 6){
        return "密码长度不能小于6个字符";
    }

    return true;
}

/**
 * 获取签名字符串（传入的数组注意排除不参与签名的字段）。
 * @param type $data
 * @return string
 */
function getSignStr($data = [])
{
    if (empty($data) || !is_array($data)){
        return "";
    }
    ksort($data);
    $signStr = '';
    foreach($data as $key => $val){
        $signStr .= $val;
    }

    return strtoupper(md5($signStr));
}

/**
 * 简单加密
 * @param type $tex
 * @param type $type
 * @param type $key
 * @return string|boolean
 */
function authSimpleKF($tex, $type = "encode", $key)
{
    $chrArr = [
        'a',
        'b',
        'c',
        'd',
        'e',
        'f',
        'g',
        'h',
        'i',
        'j',
        'k',
        'l',
        'm',
        'n',
        'o',
        'p',
        'q',
        'r',
        's',
        't',
        'u',
        'v',
        'w',
        'x',
        'y',
        'z',
        'A',
        'B',
        'C',
        'D',
        'E',
        'F',
        'G',
        'H',
        'I',
        'J',
        'K',
        'L',
        'M',
        'N',
        'O',
        'P',
        'Q',
        'R',
        'S',
        'T',
        'U',
        'V',
        'W',
        'X',
        'Y',
        'Z',
        '0',
        '1',
        '2',
        '3',
        '4',
        '5',
        '6',
        '7',
        '8',
        '9'
    ];
    if ($type == "DECODE"){
        if (strlen($tex) < 14){
            return false;
        }
        $verity_str = substr($tex, 0, 8);
        $tex = substr($tex, 8);
        if ($verity_str != substr(md5($tex), 0, 8)){
            //完整性验证失败
            return false;
        }
    }
    $key_b = $type == "DECODE" ? substr($tex, 0, 6)
        : $chrArr[rand() % 62] . $chrArr[rand() % 62] . $chrArr[rand() % 62] . $chrArr[rand() % 62] . $chrArr[rand() % 62] . $chrArr[rand() % 62];
    $rand_key = $key_b . $key;
    $rand_key = md5($rand_key);
    $tex = $type == "DECODE" ? base64_decode(substr($tex, 6)) : $tex;
    $texlen = strlen($tex);
    $reslutstr = "";
    for($i = 0; $i < $texlen; $i++){
        $reslutstr .= $tex{$i} ^ $rand_key{$i % 32};
    }
    if ($type != "DECODE"){
        $reslutstr = trim($key_b . base64_encode($reslutstr), "==");
        $reslutstr = substr(md5($reslutstr), 0, 8) . $reslutstr;
    }

    return $reslutstr;
}

/**
 * AES 加密/解密
 * @param type $str
 * @param type $type
 * @return type
 */
function aes($str, $type = "ENCODE")
{
    $key = "AESAPPCLIENT_KEY";
    $iv = "AESAPPCLIENT_KEY";
    $type = strtoupper($type);
    if (empty($str)){
        return $str;
    }
    if ($type == "ENCODE"){
        $str = base64_encode($str);
        $data = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $str, MCRYPT_MODE_CBC, $iv);

        return base64_encode($data);
    }else{
        if ($type == "DECODE" && strlen($str) > 23 && preg_match("/[^\x80-\xff]/", $str)){
            $str = base64_decode($str);
            $data = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $str, MCRYPT_MODE_CBC, $iv);

            return base64_decode($data);
        }
    }

    return $str;
}

/**
 * 发送站内信
 * @param type $userID
 * @param type $title
 * @param type $content
 * @param type $remark
 */
function sendSiteNews($userID, $type = "", $data = [], $remark = "")
{
    $logic = new \Service\News\Logic\SiteNewsLogic();

    return $logic->sendNews($userID, $type, $data, $remark);
}

/**表单提交
 * @param $url
 * @param string $method
 * @param array $post_data
 * @return bool|string
 */
function curlSubmit($url, $method = 'get', $post_data=[])
{echo $url.PHP_EOL;
    $method = strtoupper($method);
    $ch = curl_init();
    //设置选项，包括URL
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    if ($method == "GET"){
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_TIMEOUT, 1);
    }else{
        // post数据
        curl_setopt($ch, CURLOPT_POST, 1);
        // post的变量
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'Content-Type: application/json',
                'Content-Length: ' . strlen($post_data))
        );
    }

    $output = curl_exec($ch);
    curl_close($ch);
    var_dump($output);
    return $output;
}

/**
 * 校验$value是否非空
 *  if not set ,return true;
 *  if is null , return true;
 * */
function isEmpty($value)
{
    if (!isset($value)){
        return true;
    }
    if ($value === null){
        return true;
    }
    if (trim($value) === ""){
        return true;
    }
    if (is_array($value) && empty($value)){
        return true;
    }

    return false;
}

/**
 * 码串生成器
 */
function codeGenerator($num, $type = 'ENCODE')
{
    $sourceStr = 'WX8E5FC4DGH1BANPJ2RSTUV67M9KL3Y';
    $code = '';
    //加密
    if ($type == 'ENCODE'){
        $code = '';
        while($num > 0){
            $mod = $num % 31;
            $num = ($num - $mod) / 31;
            $string = $sourceStr;
            $code = $string[$mod] . $code;
        }
        if (empty($code[4])){
            $code = str_pad($code, 4, 'Q', STR_PAD_LEFT);
        }
    }elseif ($type == 'DECODE'){//解密
        if (strrpos($num, 'Q') !== false){
            $num = substr($num, strrpos($num, 'Q') + 1);
        }
        $len = strlen($num);
        $num = strrev($num);
        $code = 0;
        for($i = 0; $i < $len; $i++){
            $code += strpos($sourceStr, $num[$i]) * pow(31, $i);
        }
    }

    return $code;
}

function perr($data)
{
    echo '<pre>';
    print_r($data);
}

/**
 * 将json按明文的一定格式保存，以方便入库的时候like搜索
 */
function CardJsonToString($json = "")
{
    if (empty($json)){
        return "";
    }
    $arr = json_decode($json, true);

    return serialize($arr);
}

//字符串转成数组
function CardStringToArr($str)
{
    if (empty($str)){
        return "";
    }

    return unserialize($str);
}

/**
 * 从字符串中提取数字
 */
function getNumByStr($str)
{
    if (preg_match('/\d+/', $str, $arr)){
        return ($arr[0]) ? $arr[0] : 0;
    }else{
        return 0;
    }
}

/**
 * 从字符串中提取数字 返回所有
 */
function getNumByStrAll($str)
{
    $num = "";
    if (preg_match_all('/\d+/', $str, $arr)){
        foreach($arr[0] as $key => $value){
            $num .= $value;
        }

        return $num;
    }else{
        return 0;
    }
}

/**
 * 求整数
 */
function numInteger($num)
{
    return floor($num);
}

/**
 * 求格式化数据
 */
function timeFormat($time)
{
    $nowtime = time();
    $tmp = $nowtime - $time;
    if ($tmp <= 0){
        return "刚刚";
    }
    switch($tmp){
        case $tmp < 60 && $tmp >= 0:
            return "刚刚";
        case $tmp >= 60 && $tmp < 3600:
            return floor($tmp / 60) . "分钟前";
        case $tmp >= 3600 && $tmp < 86400:
            return floor($tmp / 3600) . "小时前";
        case $tmp >= 86400 && $tmp < 31536000:
            return date('m-d', $time);
        default:
            return date('Y-m-d', $time);
    }
}

function guid()
{
    if (function_exists('com_create_guid')){
        return com_create_guid();
    }else{
        mt_srand((double)microtime() * 10000); //optional for php 4.2.0 and up.
        $charid = strtoupper(md5(uniqid(rand(), true)));
        $uuid = substr($charid, 0, 8)
                . substr($charid, 8, 4)
                . substr($charid, 12, 4)
                . substr($charid, 16, 4)
                . substr($charid, 20, 12);

        return strtolower($uuid);
    }
}

/**
 * 过滤掉母亲或者父亲
 * @param $str
 * @return false|int
 */
function sensitive($str)
{
    if (empty($str)){
        return false;
    }

    return preg_match('/(妈|爸|父|母|公|婆|老豆)+/', $str);
}

/**
 * 短链接
 * @param $str
 * @return false|int
 */
function shortUrl($url_long)
{
    $api = 'http://api.t.sina.com.cn/short_url/shorten.json';
    $source = XINLANGAPID;
    $request_url = sprintf($api . '?source=%s&url_long=%s', $source, $url_long);
    $data = file_get_contents($request_url);
    $arr = json_decode($data, true);

    return $arr[0]['url_short'];
}

/**
 * 过滤表情
 * @param $str
 * @return null|string|string[]
 */
function filterEmoji($str)
{
    $str = preg_replace_callback(
        '/./u', function (array $match){
        return strlen($match[0]) >= 4 ? '口口口' : $match[0];
    }, $str);

    return $str;
}

/**
 * 过滤敏感字眼
 */
function filterSensitive($str)
{
    $info = M("sysSensitive")->where(['content' => $str])->field('sID')->find();
    if (empty($info)){
        return true;
    }else{
        return false;
    }
}

/**
 * 流水单号
 * @param type $traseCode
 * @return boolean
 */
function getOrderNo($traseCode)
{
    $traseCode = trim($traseCode);
    if (empty($traseCode)){
        return false;
    }
    $traseCode = substr($traseCode, -4);
    $channelCode = 'QIMAIACT';
    $uid = substr(md5(uniqid(md5(microtime(true)), true)), 0, 11);
    $arr = [
        $channelCode,
        date("Ymd"),
        $traseCode,
        $uid
    ];
    $orderNo = implode('', $arr);

    return strtoupper($orderNo);
}

/**
 * 字符串截取
 */
function strSub($str, $offset = 5, $replace = '...', $coding = 'utf-8')
{
    if (mb_strlen($str, $coding) > 6){
        return mb_substr($str, 0, $offset, $coding) . $replace;
    }

    return $str;
}

/**验证中文
 * @param $str
 * @return bool
 */
function checkChinese($str)
{
    if (preg_match('/^[\x{4e00}-\x{9fa5}]+$/u', $str)){
        return true;
    }

    return false;
}


// 阶乘
function factorial($n)
{
    return array_product(range(1, $n));
}

// 排列数
function A($n, $m)
{
    return factorial($n) / factorial($n - $m);
}

// 组合数
function C($n, $m)
{
    return A($n, $m) / factorial($m);
}

// 排列
function arrangement($a, $m)
{
    $r = [];

    $n = count($a);
    if ($m <= 0 || $m > $n){
        return $r;
    }

    for($i = 0; $i < $n; $i++){
        $b = $a;
        $t = array_splice($b, $i, 1);
        if ($m == 1){
            $r[] = $t;
        }else{
            $c = arrangement($b, $m - 1);
            foreach($c as $v){
                $r[] = array_merge($t, $v);
            }
        }
    }

    return $r;
}

// 组合
function combination($a, $m)
{
    $r = [];

    $n = count($a);
    if ($m <= 0 || $m > $n){
        return $r;
    }

    for($i = 0; $i < $n; $i++){
        $t = [$a[$i]];
        if ($m == 1){
            $r[] = $t;
        }else{
            $b = array_slice($a, $i + 1);
            $c = combination($b, $m - 1);
            foreach($c as $v){
                $r[] = array_merge($t, $v);
            }
        }
    }

    return $r;
}


/**输出
 * @param $string
 * @param string $color
 */
function stdout($string, $color = 'green')
{
    $colorArr = [
        'black' => 30,
        'red' => 31,
        'green' => 32,
        'yellow' => 33,
        'blue' => 34,
        'white' => 37

    ];


    $format = '1;1;';
    $code = $format . $colorArr[$color];

    $content = "\033[0m" . ($code !== '' ? "\033[" . $code . 'm' : '') . $string . "\033[0m";

    echo date('Y-m-d H:i:s'), '   ', $content, PHP_EOL;

}


function cpLog($log_content, $item = "Wge")
{

    $max_size = 100000000;

    $log_filename = 'cpExamilContent/' . $item . '/' . date('Y-m-d') . ".txt";
    // 自动创建日志目录
    $log_dir = dirname($log_filename);
    if (!is_dir($log_dir)){
        mkdir($log_dir, 0755, true);
    }
    if (file_exists($log_filename) && (abs(filesize($log_filename)) > $max_size)){
        unlink($log_filename);
    }
    file_put_contents($log_filename, date('Y-m-d H:i:s') . "    info ： " . var_export($log_content, true) . "\r\n", FILE_APPEND);
}


/**图片base64
 * @param $img_file
 * @return string
 */
function imgToBase64($img_file) {

    $img_base64 = '';
    if (file_exists($img_file)) {
        $app_img_file = $img_file; // 图片路径
        $img_info = getimagesize($app_img_file); // 取得图片的大小，类型等

        $fp = fopen($app_img_file, "r"); // 图片是否可读权限

        if ($fp) {
            $filesize = filesize($app_img_file);
            $content = fread($fp, $filesize);
//            $file_content = chunk_split(base64_encode($content)); // base64编码
            $file_content = base64_encode($content);
            switch ($img_info[2]) {           //判读图片类型
                case 1: $img_type = "gif";
                    break;
                case 2: $img_type = "jpg";
                    break;
                case 3: $img_type = "png";
                    break;
            }

            $img_base64 = 'data:image/' . $img_type . ';base64,' . $file_content;//合成图片的base64编码

        }
        fclose($fp);
    }

    return $img_base64; //返回图片的base64
}

/**curl
 * @param $url
 * @param $data
 * @param string $method
 * @param array $header
 * @return bool|string
 */
function curlData($url, $data, $method = 'GET', $header = [])
{
    $method = strtoupper($method);
    //初始化
    $ch = curl_init();
    !empty($header) && curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
    if ($method == 'GET'){
        if ($data){
            $querystring = http_build_query($data);
            $url = $url . '?' . $querystring;
        }
    }
    // 请求头，可以传数组
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);         // 执行后不直接打印出来
    if ($method == 'POST'){
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');     // 请求方式
        curl_setopt($ch, CURLOPT_POST, true);               // post提交
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);              // post的变量
    }
    if ($method == 'PUT'){
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    }
    if ($method == 'DELETE'){
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    }
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过证书检查
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // 不从证书中检查SSL加密算法是否存在
    $output = curl_exec($ch); //执行并获取HTML文档内容
    curl_close($ch); //释放curl句柄

    return $output;
}
