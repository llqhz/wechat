<?php

namespace Wx;
/**
 * 测试号接口的类
 */
class Wechat{

        // 开发者中心-配置项-AppID(应用ID)
    private $appId = ''; // 网创科技
        // 开发者中心-配置项-AppSecret(应用密钥)
    private $appSecret = '';    // 网创科技
        // 开发者中心-配置项-服务器配置-Token(令牌)
    private $token = '';
        // 开发者中心-配置项-服务器配置-EncodingAESKey(消息加解密密钥)
    private $encodingAESKey = '';
        // 开发者中心-微信号
    private $wechatId = '';    // 网创科技

    private $msg = [];


    public function __construct($appId='',$appSecret='',$options=[])
    {
        // 这是使用了file来保存access_token
        // 定义应用前缀
        if ( !empty($appid) ) {
            $this->appId = $appId;
            $this->appSecret = $appSecret;
        }
        if ( is_array($options) && (!empty($options)) ) {
            $this->token = $options['token'] ?: '';
            $this->encodingAESKey = $options['encodingAESKey'] ?: '';
            $this->wechatId = $options['wechatId'] ?: '';
        }

        cache([
            'type'=>'File',
            'prefix'=> 'wx_com_',
            'expire'=>7200,
            'path' => CACHE_PATH
        ]);
    }

    /**
     * 首次接口验证
     * @return [type] [description]
     */
    public function valid()
    {
        $echoStr = $_GET["echostr"];
        //valid signature , option
        if( $this->checkSignature() ){
            if ( isset($_GET["echostr"]) ) {
                echo $echoStr;
                exit;
            }
        } else {
            echo "验证失败!";
            exit;
        }
    }

    /**
     * 接口验证的实现
     * @return [type] [description]
     */
    private function checkSignature()
    {
        //排序,连接,加密
        $token = $this->token;
        $signature = $_GET["signature"];
        $timestamp = $_GET["timestamp"];
        $nonce = $_GET["nonce"];

        $tmpArr = array($token, $timestamp, $nonce);
        // use SORT_STRING rule
        sort($tmpArr, SORT_STRING);
        $tmpStr = implode( $tmpArr );
        $tmpStr = sha1( $tmpStr );

        if( $tmpStr == $signature ){
            return true;
        }else{
            return false;
        }
    }

    public function obj2arr($obj)
    {
        $arr = get_object_vars($obj);
        foreach ($arr as $key => $val) {
            if ( is_object($val) ) {
                $arr[$key] = $this->obj2arr($val);
            }
        }
        return $arr;
    }


    /**
     * 获取微信msg对象
     * @return array Msg
     */
    public function getMsg()
    {
        /*  微信post的xml
        <xml>
            <ToUserName><![CDATA[toUser]]></ToUserName>
            <FromUserName><![CDATA[fromUser]]></FromUserName>
            <CreateTime>1348831860</CreateTime>
            <MsgType><![CDATA[image]]></MsgType>
            <PicUrl><![CDATA[this is a url]]></PicUrl>
            <MediaId><![CDATA[media_id]]></MediaId>
            <MsgId>1234567890123456</MsgId>
        </xml>
        */

        //1.获取到微信推送过来post数据（xml格式）
        // 获取微信原始消息体
        if (@file_get_contents('php://input') !== false) {
            $xml_input = file_get_contents('php://input');
        } else {
            $xml_input = $GLOBALS['HTTP_RAW_POST_DATA'];
        }

        if (!empty($xml_input)) {
            //2.解析微信xml,得到msg对象微信消息体
            libxml_disable_entity_loader(true); // 安全过滤,禁止引入外部实体
            $xml_obj = simplexml_load_string($xml_input, 'SimpleXMLElement', LIBXML_NOCDATA);

            //保存当前15秒内处理的消息到队列,每次事件在队列中对比以决定是否处理
            $arr = $this->obj2arr($xml_obj);
            if ( $this->checkMsg($arr) ) {
                //检查通过,返回并处理
                return $this->Msg = $arr;
            } else {
                //如有重复
                echo "success";
                exit;
            }
        } else {
            echo "error";
            exit;
        }
    }

    /**
     * 消息重复检测
     * @param  [type] $msg [description]
     * @return [type]      [description]
     */
    private function checkMsg($msg)
    {
        if ( isset($msg['MsgId']) ) {
            //  array( [MsgId,time] )
            $msg_queue =cache('wx_msg_queue');
            // 第一次,创建新队列
            if ( !is_array($msg_queue) ) {
                $msg_queue = [];
            }
            $res = true;
            foreach ($msg_queue as $k => $v) {
                // 判断重复
                if ( $msg['MsgId'] == $v['MsgId'] ) {
                    $res = false;
                }
                // 判断过期
                if (  intval($v['time']) < intval(time()-15) ) {
                    unset($msg_queue[$k]);
                }
            }
            if ( $res == true ) {
                $msg_queue[] = [ 'MsgId'=>$msg['MsgId'],'time'=>time()];
            }
            cache('wx_msg_queue',$msg_queue);
            return $res;
        } else {
            $event_queue = cache('wx_event_queue');
            $checkStr = $msg['FromUserName'].$msg['CreateTime'];

            // 第一次创建新队列
            if ( $event_queue === false ) {
                $event_queue = [];
            }
            $res = true;
            foreach ($event_queue as $k => $v) {
                if ( $checkStr == $v ) {
                    $res = false;
                }

                $ctime = intval(substr($v,-10));
                if ( $ctime < intval(time()-15) ) {
                    unset($event_queue[$k]);
                }
            }

            if ( $res == true ) {
                $event_queue[] = $checkStr;
            }
            cache('wx_event_queue',$event_queue);
            return $res;
        }
    }


    /**
     * 回复消息
     * @param  [type] $content [description]
     * @param  string $msgType [description]
     * @return [type]          [description]
     */
    public function reply2($content,$msgType='text',$opt=[])
    {
        $fromUser = $this->Msg['ToUserName'];
        $toUser = $this->Msg['FromUserName'];
        $ctime = time();

        switch ($msgType) {
            case 'text':
            case 'arr':
                $content = print_r($content,true);
                $content = mb_substr($content,0,2048);
                $template = "<xml>
                            <ToUserName><![CDATA[%s]]></ToUserName>
                            <FromUserName><![CDATA[%s]]></FromUserName>
                            <CreateTime>%s</CreateTime>
                            <MsgType><![CDATA[text]]></MsgType>
                            <Content><![CDATA[%s]]></Content>
                            </xml>";
                echo sprintf($template,$toUser,$fromUser,$ctime,$content);
                exit;
                break;

            case 'news':
                $template = "<xml>
                            <ToUserName><![CDATA[%s]]></ToUserName>
                            <FromUserName><![CDATA[%s]]></FromUserName>
                            <CreateTime>%s</CreateTime>
                            <MsgType><![CDATA[%s]]></MsgType>
                            <ArticleCount>".count($content)."</ArticleCount>
                            <Articles>";
                foreach ($content as $k => $v) {
                    $template.= "<item>
                                <Title><![CDATA[".$v['title']."]]></Title>
                                <Description><![CDATA[".$v['description']."]]></Description>
                                <PicUrl><![CDATA[".$v['picurl']."]]></PicUrl>
                                <Url><![CDATA[".$v['url']."]]></Url>
                                </item>";
                }
                $template.= "</Articles></xml>";
                echo sprintf($template,$toUser,$fromUser,$ctime,$msgType);
                exit;
                break;
            case 'image':
                $template = "<xml>
                            <ToUserName><![CDATA[%s]]></ToUserName>
                            <FromUserName><![CDATA[%s]]></FromUserName>
                            <CreateTime>%s</CreateTime>
                            <MsgType><![CDATA[%s]]></MsgType>
                            <Image><MediaId><![CDATA[%s]]></MediaId></Image>
                            </xml>";
                echo sprintf($template,$toUser,$fromUser,$ctime,$msgType,$content);
                exit;
                break;
            case 'voice':
                $template = "<xml>
                            <ToUserName><![CDATA[%s]]></ToUserName>
                            <FromUserName><![CDATA[%s]]></FromUserName>
                            <CreateTime>%s</CreateTime>
                            <MsgType><![CDATA[%s]]></MsgType>
                            <Voice><MediaId><![CDATA[%s]]></MediaId></Voice>
                            </xml>";
                echo sprintf($template,$toUser,$fromUser,$ctime,$msgType,$content);
                exit;
                break;
            case 'music':
                $template = "<xml><ToUserName><![CDATA[%s]]></ToUserName>
                             <FromUserName><![CDATA[%s]]></FromUserName>
                             <CreateTime>%s</CreateTime>
                             <MsgType><![CDATA[music]]></MsgType>
                             <Music>
                                <Title><![CDATA[$s]]></Title>
                                <Description><![CDATA[%s]]></Description>
                                <MusicUrl><![CDATA[%s]]></MusicUrl>
                            </Music>
                            </xml>";
                echo sprintf($template,$toUser,$fromUser,$ctime,$op['Title'],$op['Description'],$op['MusicUrl']);
                exit;
                break;
            case 'video':
                $template = "<xml>
                            <ToUserName><![CDATA[%s]]></ToUserName>
                            <FromUserName><![CDATA[%s]]></FromUserName>
                            <CreateTime>%s</CreateTime>
                            <MsgType><![CDATA[%s]]></MsgType>
                            <Video>
                                <MediaId><![CDATA[%s]]></MediaId>
                                <Title><![CDATA[%s]]></Title>
                                <Description><![CDATA[%s]]></Description>
                            </Video>
                            </xml>";
                echo sprintf($template,$toUser,$fromUser,$ctime,$msgType,$content,$op['title']);
                exit;
                break;

            default:
                # code...
                break;
        }
    }

    /**
     * 回复消息
     * @param  [type] $content [description]
     * @param  string $msgType [description]
     * @return [type]          [description]
     */
    public function reply($content,$msgType='text')
    {
        $data = array(
                'ToUserName' => $this->Msg['FromUserName'],
                'FromUserName' => $this->Msg['ToUserName'],
                'CreateTime' => time(),
                'MsgType' => $msgType,
            );

        switch ($msgType) {
            /**
             * $content = $content;
             */
            case 'arr':
                $data['MsgType'] = 'text';
            case 'text':
                $content = print_r($content,true);
                $content = mb_substr($content,0,2048);
                $data['Content'] = $content;
                break;

            /**
             * $content = array(
             *     array(
             *             'Title' => '',
             *             'Description' = > '',
             *             'PicUrl' = > '',
             *             'Url' = > '',
             *          ),
             *     array(
             *             'Title' => '',
             *             'Description' = > '',
             *             'PicUrl' = > '',
             *             'Url' = > '',
             *          )
             * );
             */
            case 'news':
                $data['ArticleCount'] = count($content);
                $data['Articles'] = $content;
                break;

            /**
             * $content = $MediaId;
             */
            case 'image':
                $data['Image'] = array('MediaId'=>$content);
                break;

            /**
             * array (
             *    Title    否   音乐标题
             *    Description 否   音乐描述
             *    MusicUrl    否   音乐链接
             *    HQMusicUrl  否   高质量音乐链接，WIFI环境优先使用该链接播放音乐
             *    ThumbMediaId    否   缩略图的媒体id，通过素材管理中的接口上传多媒体文件，得到的id
             *  )
             */
            case 'music':
                $data['Music'] = $content;
                break;

            /**
             * $content = $MediaId;
             */
            case 'voice':  // MediaId
                $data['Voice'] = array('MediaId'=>$content);
                break;

            /**
             * $content = array(
             *      'MediaId' => '',
             *      'Title' => '',
             *      'Description' => '',
             *   );
             */
            case 'video':
                $data['Video'] = $content;
                break;

            default:
                # code...
                break;
        }
        $xml = arrayToXml($data);
        echo $xml;
        cache('xml',$xml);
        exit();
    }

    /**
     * 获取微信全局access_token
     * @param  boolen $refresh 是否刷新
     * @return access_token
     */
    public function getToken( $refresh=false ){
        $token =cache('token');
        if ( ($token == false) || ($refresh == true) ) {
             $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=".$this->appId."&secret=".$this->appSecret;

             $data = $this->httpCurl($url);
             $token = $data['access_token'];
             cache('token',$token,7200);
             return $token;
        }

        //验证token有效性
        $status = $this->checkToken($token);
        if ( $status === false ) {
            return $this->getToken(true);
        } else {
            return $token;
        }

    }


    /**
     * httpCurl 支持get/post和http/https
     * @param  [type] $url     [description]
     * @param  string $method  [description]
     * @param  string $resType 返回值类型,默认str,取值: arr
     * @param  array|str  $data    method为post时,需要post的数据 兼容数组和jsonStr
     * @return mixed           返回array或者string
     */
    public function httpCurl( $url, $method='get', $resType='arr', $data=[] ) {

        $ch = curl_init();

        //设置url和返回
        curl_setopt($ch,CURLOPT_URL,$url);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);

        if ( $method == 'post' ) {
            //开启post
            curl_setopt($ch,CURLOPT_POST,1);
            //设置post数据
            curl_setopt($ch,CURLOPT_POSTFIELDS,$data);
        }

        $str = curl_exec($ch);
        curl_close($ch);

        if ( $resType == 'arr' ) {
            return json_decode($str,true);
        } else {
            return $str;
        }
    }


    /**
     * 获取微信ip列表
     * @return [type] [description]
     */
    public function getIpList()
    {
        $access_token = $this->getToken();
        $url = "https://api.weixin.qq.com/cgi-bin/getcallbackip?access_token=".$access_token;
        $data = $this->httpCurl($url);
        return $data['ip_list'];
    }

    /**
     * 验证token有效性
     * @return [type] [description]
     */
    public function checkToken($token)
    {
        $url = "https://api.weixin.qq.com/cgi-bin/getcallbackip?access_token=".$token;
        $data = $this->httpCurl($url,'get','arr');

        if ( $data['errcode'] == 40014 || $data['errcode'] == 40001 ) { //access_token过期
            return false;
        } else {
            return true;
        }
    }

    /**
     * 获取微信全局ticket
     * @param  boolen $refresh 是否刷新
     * @return [type] [description]
     */
    public function getTicket( $refresh=false )
    {
        $ticket = cache('ticket');

        /*如果ticket过期或者强制刷新*/
        if ( (!$ticket) || $refresh == true ) {
            //1 获取token
            $token = $this->getToken();

            //2 用token换取 ticket
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=".$token."&type=jsapi";
            $data = $this->httpCurl($url);

            //3 缓存ticket
            $ticket = $data['ticket'];
           cache('ticket',$ticket,7200);
        }

        return $ticket;
    }

    /**
     * 微信登录
     * @return [type] [description]
     */
    public function wxLogin($redirect_uri)
    {
        $appId = $this->appId;
        $redirect_uri = urlencode($redirect_uri);
        $url = "https://open.weixin.qq.com/connect/qrconnect?appid=".$appId."&redirect_uri=".$redirect_uri."&response_type=code&scope=snsapi_login&state=state#wechat_redirect";
        header("location:".$url);
    }

    /**
     * 生成随机字字符串nonceStr
     * @param  integer $len [description]
     * @return [type]       [description]
     */
    public function getRandStr($len=16)
    {
        $arr = [];
        for ($i=48; $i <= 57; $i++) {
            $arr[] = chr($i);
        }
        for ($i=65; $i <= 90; $i++) {
            $arr[] = chr($i);
        }
        for ($i=97; $i <= 122; $i++) {
            $arr[] = chr($i);
        }
        $str = implode('',$arr);

        $res = '';
        for ($i=0; $i < $len; $i++) {
            $res .= $str[rand(0,strlen($str)-1)];
        }

        return $res;
    }


    /**
     * jsSdk验证
     * @return array 返回jssdk参数 timestamp,nonceStr,signature
     */
    public function jsSdk($url)
    {
        //1 获取参数
        $ticket = $this->getTicket();

        //REQUEST_SCHEME => http   HTTP_HOST => www.llqhz.cn REQUEST_URI => /wx/home/wx/share.html?id=2
        $location = $url;
        $timestamp = time();
        $nonceStr = $this->getRandStr();

        //2 拼接成字符串string1
        $str = "jsapi_ticket=".$ticket."&noncestr=".$nonceStr."&timestamp=".$timestamp."&url=".$location;

        //3 sha1加密
        $signature = sha1($str);

        //4 返回结果
        $data = array(
                'appId'     => $this->appId,
                'timestamp' => $timestamp,
                'nonceStr'  => $nonceStr,
                'signature' => $signature
            );

        return $data;
    }

    /**
     * jsSdk验证
     * @return array 返回jssdk参数 timestamp,nonceStr,signature
     */
    public function jsSdkCheck()
    {
        //1 获取参数
        $ticket = $this->getTicket();

        //REQUEST_SCHEME => http   HTTP_HOST => www.llqhz.cn REQUEST_URI => /wx/home/wx/share.html?id=2
        $location = $_SERVER['REQUEST_SCHEME'].'://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
        $timestamp = time();
        $nonceStr = $this->getRandStr();

        //2 拼接成字符串string1
        $str = "jsapi_ticket=".$ticket."&noncestr=".$nonceStr."&timestamp=".$timestamp."&url=".$location;

        //3 sha1加密
        $signature = sha1($str);

        //4 返回结果
        $data = array(
                'appId'  => $this->appId,
                'timestamp' => $timestamp,
                'nonceStr'  => $nonceStr,
                'signature' => $signature
            );

        return $data;
    }

    /**
     * 设置自定义菜单,成功返回true 失败返回错误码code
     * @param  菜单数量:3->5  菜单字数4->7
     * @param  [type] $jsonStr [description]
     * @return true/code     成功返回true 失败返回错误码code
     */
    public function setMenu($jsonStr,$token='')
    {

        /*按钮示例*/
        /*'{"button":[
            {
                "name": "按钮1",
                "type": "view",
                "url" : "http://www.soso.com/"
            },
            {
                "name": "多级按钮",
                "sub_button": [
                                 {
                                    "name": "按钮2-1",
                                    "type": "view",
                                    "url" : "http://www.baidu.com/"
                                 },
                                 {
                                    "name": "按钮2-2",
                                    "type": "view",
                                    "url" : "http://www.llqhz.cn/"
                                 }
                              ]
            }
        ]}';*/

        if ( !$token ) {
            $token = $this->getToken();
        }

        $jsonStr = json_encode(json_decode($jsonStr,true),JSON_UNESCAPED_UNICODE);
        $url = "https://api.weixin.qq.com/cgi-bin/menu/create?access_token=".$token;
        $data = $this->httpCurl($url,'post','arr',$jsonStr);
        if ( $data['errcode'] == 0 ) {
            return true;
        } else {
            return $data['errmsg'];
        }
    }

    /**
     * 返回便于php处理的数组菜单
     * @param  string $token [description]
     * @return [type]        [description]
     */
    public function getMenu($token='')
    {
        if ( !$token ) {
            $token = $this->getToken();
        }

        $url = "https://api.weixin.qq.com/cgi-bin/menu/get?access_token=".$token;
        $data = $this->httpCurl($url);

        return $data['menu'];
    }


    /**
     * 获取已经关注用户基本信息
     * @param  [type] $openId [description]
     * @return [type]         [description]
     */
    public function getInfo($openId)
    {
        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/cgi-bin/user/info?access_token=".$token."&openid=".$openId."&lang=zh_CN";

        $data = $this->httpCurl($url);

        if ( isset( $data['errcode'] ) ) {
            return $data['errcode'];
        } else {
            return $data;
        }
    }

    public function authGetCodeUrl($state='info')
    {
        $location = 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];

        $location = urlencode($location);

        $url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=".$this->appId."&redirect_uri=".$location."&response_type=code&scope=snsapi_userinfo&state=".$state."#wechat_redirect";

        return $url;
    }

    public function authGetInfo($opt=[])
    {
        if ( !((isset($opt['code'])) || isset($opt['refresh_token'])) ) {
            return -2;   // 没有code和refresh_token  需要重新跳转授权
        }

        if ( isset($opt['code']) ) {   // 存在code
            $code = $opt['code'];
            //使用code换取oauth2的授权access_token
            $url_token = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=".$this->appId."&secret=".$this->appSecret."&code=".$code."&grant_type=authorization_code";
            $tokens = httpCurl($url_token,'get','arr');
            $token = $tokens['access_token'];
            $openid = $tokens['openid'];
            $refresh_token = $tokens['refresh_token'];
            cookie('refresh_token',$refresh_token,2505600);
            cookie('openid',$openid,2505600);
        }
        if ( isset($opt['refresh_token']) ) {   // 存在refresh_token
            $refresh_token = $opt['refresh_token'];
            $refresh_url = "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=".$this->appId."&grant_type=refresh_token&refresh_token=".$refresh_token;
            $tokens = httpCurl($refresh_url,'get','arr');
            $token = $tokens['access_token'];
            if ( empty($token) ) {
                cookie('refresh_token',null);
                return -1;  // refresh_token 无效
            }
            $openid = $tokens['openid'];
        }

        //保存用户openid
        session('openid',$openid);

        //使用获取的access_token获取用户信息
        $url_info = "https://api.weixin.qq.com/sns/userinfo?access_token=".$token."&openid=".$openid.'&lang=zh_CN';
        $info = httpCurl($url_info,'get','arr');

        if ( empty($info['openid']) ) {
            return -3;     // 获取用户信息出错
        }
        //返回用户信息
        return $info;
    }

    public function authGetBase($code='')
    {
        if ( empty($code) ) {
            return false;
        }
        $url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid='.$this->appId.'&secret='.$this->appSecret.'&code='.$code.'&grant_type=authorization_code';
        $arr = httpCurl($url,'get','arr');
        $openid = $arr['openid'];
        if ( empty($openid) ) {
            return false;
        }
        return $openid;
    }



    public function authGetUserInfo()
    {
        //1 通过code换取token和openid
        //2 通过refresh换取token和openid
        $refresh_token = cookie('refresh_token');
        if ( !empty($refresh_token) ) {
            $refresh_url = "https://api.weixin.qq.com/sns/oauth2/refresh_token?appid=".$this->appId."&grant_type=refresh_token&refresh_token=".$refresh_token;


            $res = $this->httpCurl($refresh_url,'get','arr');
            $token = $res['access_token'];
            if ( empty($token) ) {
                cookie('refresh_token',null);
                redirect($this->authGetCodeUrl());
            }
            $openid = $res['openid'];
        } else {
            $code = $_GET['code'];
            //使用code换取oauth2的授权access_token
            $url_token = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=".$this->appId."&secret=".$this->appSecret."&code=".$code."&grant_type=authorization_code";

            $tokens = $this->httpCurl($url_token,'get','arr');

            $token = $tokens['access_token'];
            $openid = $tokens['openid'];
            $refresh_token = $tokens['refresh_token'];
            cookie('refresh_token',$refresh_token,2505600);
            cookie('openid',$openid,2505600);
        }

        //保存用户openid
        session('openid',$openid);

        //使用获取的access_token获取用户信息
        $url_info = "https://api.weixin.qq.com/sns/userinfo?access_token=".$token."&openid=".$openid.'&lang=zh_CN';
        $info = $this->httpCurl($url_info,'get','arr');


        if ( empty($info['openid']) ) {
            return -3;     // 获取用户信息出错
        }
        //返回用户信息
        return $info;
    }


    /**
     * 获取用户列表 支持最多10000个
     * @return arr 用户列表
     */
    public function getUserList()
    {
        $token = $this->getToken();

        $url = 'https://api.weixin.qq.com/cgi-bin/user/get?access_token='.$token;

        $data = $this->httpCurl($url);

        if ( isset( $data['errcode'] ) ) {
            return $data['errcode'];
        } else {
            return $data;
        }
    }

    /**
     * 为用户设置备注
     * @param  [type] $openId [description]
     * @param  [type] $remark [description]
     * @return [type]         [description]
     */
    public function remarkUser($openId,$remark)
    {
        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/cgi-bin/user/info/updateremark?access_token=".$token;

        $jsonStr = '{
                    "openid":"'.$openId.'",
                    "remark":"'.$remark.'"
                }';

        $data = $this->httpCurl($url,'post','arr',$jsonStr);

        if ( $data['errcode'] == 0 ) {
            return true;
        } else {
            return $data['errcode'];
        }
    }

    /**
     * 获取黑名单列表
     * @return [type] [description]
     */
    public function blackUserList()
    {
        $token = $this->getToken();

        $url = 'https://api.weixin.qq.com/cgi-bin/tags/members/getblacklist?access_token='.$token;

        $begin = '{
                    "begin_openid":""
                }';

        $data = $this->httpCurl($url,'post','arr',$begin);

        if ( isset( $data['errcode'] ) ) {
            return $data['errcode'];
        } else {
            return $data;
        }
    }

    /**
     * 生成场景值的二维码,可用于统计关注来源(eg:门店1扫码关注)
     * @param 永久二维码参数  id:场景值
     * @param  boolen $isPerm 是否是永久
     * @param 临时二维码参数  expire:过期时间  id:场景值
     * @return [type]        [description]
     */
    public function getQRCode($id='1001',$isPerm=false,$expire=604800)
    {
        //1 获取token
        $token = $this->getToken();

        //2 用token换取ticket
        $url = "https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=".$token;

        if ( $isTemp == true ) {
            $postStr = '{"expire_seconds": '.$expire.',"action_name":"QR_STR_SCENE","action_info": {"scene":{"scene_str": "'.$id.'"}}}';
        } else {
            $postStr = '{"action_name": "QR_LIMIT_STR_SCENE", "action_info": {"scene": {"scene_str": "'.$id.'"}}}';
        }

        $data = $this->httpCurl($url,'post','arr',$postStr);

        if ( isset( $data['errcode'] ) ) {
            return false;
        }

        //3 用ticket拼接处img的url
        $QRUrl = "https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=".urlencode($data['ticket']);
        return $QRUrl;

    }


    /**
     * 素材上传接口
     * @param  string  $file   文件路径
     * @param  string  $type   微信允许的文件类型
     * @param  boolean $isPerm 是否是永久素材
     * @return arr          返回代码和返回说明
     */
    public function uploadMedia($file,$type,$isPerm=false,$op=[])
    {
        $token = $this->getToken();

        $allowType = array('image','voice','video','thumb');

        if ( !in_array( $type ,$allowType ) ) {
            $errMsg = '允许的文件类型:'."'image','voice','video','thumb'";
            return ['errcode'=>40004];
        }
        if ( $isPerm ) { // 是否永久
            $url = "https://api.weixin.qq.com/cgi-bin/material/add_material?access_token=".$token."&type=".$type;
        } else {
            $url = "https://api.weixin.qq.com/cgi-bin/media/upload?access_token=".$token."&type=".$type;
        }


        $this->checkImg($file); // 下载文件

        $data = array('media'=>'@'.$file);


        /**
         * {
            "title":VIDEO_TITLE,
            "introduction":INTRODUCTION
         * }
         */
        if ( $type == 'video' ) {

            $data['description'] = json_encode($op);
        }
        $res = $this->httpCurl($url,'post','arr',$data);

        if ( isset($res['errcode']) ) {
            return $res;
        } else {
            return $res;
        }
    }

    public function getMsgImg($type="id")
    {
        $picurl = $this->Msg['PicUrl'];
        $mediaid = $this->Msg['MediaId'];
        switch ( strtolower($type) ) {
            case 'id':
                return $mediaid;
                break;
            case 'url':
                return $picurl;
                break;
            default:
                return array($mediaid,$picurl);
                break;
        }
    }



    /**
     * 下载图片到本地再推送
     * @param  [type] &$file [description]
     * @return [type]        [description]
     */
    private function checkImg(&$file)
    {
        $root = APP_PATH.'public/files/';
        if ( !file_exists($root) ) {
            mkdir($root,0777,true);
        }
        $name = pathinfo($file);
        $name = $name['basename'];
        $prefix = substr($file,0,4);
        if ( $prefix == 'http' ) {
            $file = file_get_contents($file);
            $name = $root.$name;
            file_put_contents($name,$file);
            $file = $name;
        }
    }

    /**
     * 素材获取接口
     * @param  [type]  $media_id [description]
     * @param  boolean $isVideo  [description]
     * @return [type]            [description]
     */
    public function getMedia($media_id,$isVideo=false)
    {
        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/cgi-bin/media/get?access_token=".$token."&media_id=".$media_id;
        if ( $isVideo == false ) {
            return $url;
        } else {
            //视频素材
            $data = $this->httpCurl($url,'get','arr');
            return $data['video_url'];
        }
    }

    public function getMediaList()
    {
        $res = [];
        $allowType = ['image','voice','video','thumb'];
        foreach ($allowType as $v) {
            $res[$v] = $this->_getMediaList($v);
        }
        return $res;
    }

    public function _getMediaList($type='image',$offset=0)
    {
        $arr = [];
        $token = $this->getToken();
        $url = 'https://api.weixin.qq.com/cgi-bin/material/batchget_material?access_token='.$token;
        $op = array(
                 "type" => $type,
                 "offset" => $offset,
                 "count" => 20
            );
        $data = json_encode($op);
        $res = httpCurl($url,'post','arr',$data);
        dump($res);die();
        if ( !empty($res['item']) ) {
            $arr = array_merge($arr,$res['item']);
            if ( $res['total_count'] > ($offset+20) ) {
                sleep(5);
                $res = $this->_getMediaList($type,$offset+20);
                $arr = array_merge($arr,$res['item']);
            }
        }
        return $arr;
    }

/*    public function getRand($arr,$refresh=false)
    {

        $hb = D('HBRand');
        $hb->setData([300,500,7,1211]);
        return $hb->getHBRand();
    }*/


    /**
     * 添加客服账号
     * @param string $id   客服的唯一标识
     * @param [type] $name 客服的昵称
     */
    public function addWaiter($id='001',$name='name1')
    {
        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/customservice/kfaccount/add?access_token=".$token;

        $jsonStr = '{
                         "kf_account" : "'.$id.'@'.$this->wechatId.'",
                         "nickname" : "'.$name.'",
                         "password" : "'.md5($this->token).'",
                    }';

        $data = $this->httpCurl($url,'post','arr',$jsonStr);
        if ( $data['errcode'] == 0 ) {
            return true;
        } else {
            return $data['errcode'];
        }
    }

    /**
     * 修改客服账号
     * @param [type] $id   [description]
     * @param [type] $name [description]
     */
    public function changeWaiter($id='001',$name='name1')
    {
        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/customservice/kfaccount/update?access_token=".$token;

        $jsonStr = '{
                         "kf_account" : "'.$id.'@'.$this->wechatId.'",
                         "nickname" : "'.$name.'",
                         "password" : "'.md5($this->token).'",
                    }';

        $data = $this->httpCurl($url,'post','arr',$jsonStr);
        if ( $data['errcode'] == 0 ) {
            return true;
        } else {
            return $data['errcode'];
        }
    }

    /**
     * 删除客服账号
     * @param [type] $id   [description]
     * @param [type] $name [description]
     */
    public function delWaiter($id='001',$name='name1')
    {
        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/customservice/kfaccount/del?access_token=".$token;

        $jsonStr = '{
                         "kf_account" : "'.$id.'@'.$this->wechatId.'",
                         "nickname" : "'.$name.'",
                         "password" : "'.md5($this->token).'",
                    }';

        $data = $this->httpCurl($url,'post','arr',$jsonStr);
        if ( $data['errcode'] == 0 ) {
            return true;
        } else {
            return $data['errcode'];
        }
    }


    /**
     * 上传客服头像
     * @param  string $id  客服的id
     * @param  uri $img 图片的路径,必须是jpg格式 最佳640*640
     * @return [type]      [description]
     */
    public function uploadHeadImg($id,$img)
    {
        $token = $this->getToken();

        $url = "http://api.weixin.qq.com/customservice/kfaccount/uploadheadimg?access_token={$tiken}&kf_account={$id}";

        $data = array('media'=>'@'.$img);

        $res = $this->httpCurl($url,'post','arr',$data);

        if ( $res['errcode'] == 0 ) {
            return true;
        } else {
            return $res['errcode'];
        }

    }

    /**
     * 获取所有客服
     * @param  string $value [description]
     * @return [type]        [description]
     */
    public function getWaiter()
    {
        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/cgi-bin/customservice/getkflist?access_token=".$token;

        $data = $this->httpCurl($url,'get','arr');
        if ( isset($data['errcode']) ) {
            return $data['errcode'];
        } else {
            return $data['kf_list'];
        }
    }

    /**
     * 发送客服消息
     * @param  [type] $openId  [description]
     * @param  [type] $msgType [description]
     * @param  [type] $content [description]
     * @return [type]          [description]
     */
    public function sendMsg2($openid,$content='',$msgType='text',$options=[])
    {
        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=".$token;

        switch ( strtolower( $msgType ) ) {
            case 'text':
                 $content = print_r($content,true);
                 $content = mb_substr($content,0,2048);
                 $jsonStr = '{
                                "touser":"'.$openid.'",
                                "msgtype":"text",
                                "text":
                                {
                                     "content":"'.$content.'"
                                }
                            }';
                break;

            case 'image':
            case 'voice':
            case 'video':
                $jsonStr = '{
                                "touser":"'.$openid.'",
                                "msgtype":"'.$msgType.'",
                                "voice":
                                {
                                  "media_id":"'.$content.'"
                                }
                            }';
                break;

            case 'wxcard':
                $jsonStr = '{
                              "touser":"'.$openid.'",
                              "msgtype":"wxcard",
                              "wxcard":{
                                       "card_id":"'.$content.'"
                                        },
                            }';
                break;

            case 'news':
                $news = '';
                $newstpl = '{
                                 "title":"%s",
                                 "description":"%s",
                                 "url":"%s",
                                 "picurl":"%s"
                             },';
                foreach ($content as $key => $v) {
                    $news .= sprintf($newstpl,$v['title'],$v['description'],$v['url'],$v['picurl']);
                }
                $news = rtrim($news,',');
                break;


            default:
                # code...
                break;
        }

        $data = $this->httpCurl($url,'post','arr',$jsonStr);

        if ( $data['errcode'] == 0 ) {
            return true;
        } else {
            return $data['errcode'];
        }
    }
        /**
     * 发送客服消息
     * @param  [type] $openId  [description]
     * @param  [type] $msgType [description]
     * @param  [type] $content [description]
     * @return [type]          [description]
     */
    public function sendMsg($openid,$content='',$msgtype='text')
    {
        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=".$token;

        $data = array(
                'touser' => $openid,
                'msgtype' => $msgtype,
            );

        switch ( strtolower( $msgtype ) ) {
            case 'text':
                 $content = print_r($content,true);
                 $content = mb_substr($content,0,2048);
                 $data[$msgtype] = array('content'=>$content);
                break;
            /**
             * $content = mediaid
             */
            case 'image':
            case 'voice':
                $data[$msgtype] = array('media_id'=>$content);
                break;
            /**
             * {
                  "media_id":"MEDIA_ID",
                  "thumb_media_id":"MEDIA_ID",
                  "title":"TITLE",
                  "description":"DESCRIPTION"
                }
             */
            case 'video':
                $data[$msgtype] = $content;
                break;

            case 'music':
                /**
                 * {
                      "title":"MUSIC_TITLE",
                      "description":"MUSIC_DESCRIPTION",
                      "musicurl":"MUSIC_URL",
                      "hqmusicurl":"HQ_MUSIC_URL",
                      "thumb_media_id":"THUMB_MEDIA_ID"
                    }
                 */
                $data[$msgtype] = $content;
                break;

            case 'wxcard':
                $data[$msgtype] = array('cardid'=>$content);
                break;
            /**
             * [
                 {
                     "title":"Happy Day",
                     "description":"Is Really A Happy Day",
                     "url":"URL",
                     "picurl":"PIC_URL"
                 },
                 {
                     "title":"Happy Day",
                     "description":"Is Really A Happy Day",
                     "url":"URL",
                     "picurl":"PIC_URL"
                 }
                ]
             */
            case 'news':
                $news = array();
                foreach ($content as $key => $val) {
                    $item = array();
                    foreach ($val as $k => $v) {
                        $item[strtolower($k)] = $v;
                    }
                    $news[] = $item;
                }
                $data[$msgtype] = array('articles'=>$news);
                break;

            default:
                # code...
                break;
        }

        $data = $this->httpCurl($url,'post','arr',json_encode($data,JSON_UNESCAPED_UNICODE));

        if ( $data['errcode'] == 0 ) {
            return true;
        } else {
            return $data['errcode'];
        }
    }

    /*
    {{first.DATA}}
    用户昵称：{{nickname.DATA}}
    相似度评分：{{score.DATA}}
    主图真实性：{{live1.DATA}}
    副图真实性：{{live2.DATA}}
    人物类型：{{type.DATA}}
    人脸置信度：{{face_probability.DATA}}
    性别：{{gender.DATA}}
    年龄：{{age.DATA}}
    相貌评分(参考)：{{beauty.DATA}}
    {{remark.DATA}}
    */
    public function sendTmpMsg($openid,$data,$templateId='')
    {
        $info = $this->getInfo($openid);
        $nickname = $info['nickname'];
        if ( empty($templateId) ) {
            return false;
        }
        if ( $templateId == 'RLSB' ) { //人脸识别
            $templateId = "dYaMUG5hDSovu6GLMdE7AZpl33-latE19ZjtzDjJFAg";
            $tmp = array(
                    'first' => array(
                        'value' => $nickname.' 当前的人脸识别结果如下',
                        'color' => '#63b359'
                    ),
                    'score' => array(
                        'value' => $data['score'],
                        'color' => '#cc463d'
                    ),
                    'live1' => array(
                        'value' => $data['live1'],
                        'color' => '#509fc9'
                    ),
                    'live2' => array(
                        'value' => $data['live2'],
                        'color' => '#509fc9'
                    ),
                    'type' => array(
                        'value' => $data['type'],
                        'color' => '#509fc9'
                    ),
                    'face_probability' => array(
                        'value' => $data['face_probability'],
                        'color' => '#509fc9'
                    ),
                    'gender' => array(
                        'value' => $data['gender'],
                        'color' => '#509fc9'
                    ),
                    'age' => array(
                        'value' => $data['age'],
                        'color' => '#509fc9'
                    ),
                    'beauty' => array(
                        'value' => $data['beauty'],
                        'color' => '#509fc9'
                    ),
                    'remark' => array(
                        'value' => '以上结果仅供参考,谢谢您的使用',
                        'color' => '#2c9f67'
                    )
                );
            $data = $tmp;
        }

        if ( $templateId == 'SMDL' ) { //扫码登录
            $templateId = "dQ80-R0djf6S8oPsdPlEvbKq3AbVb5ErD6-wP16kcGw";
            $tmp = array(
                    'first' => array(
                        'value' => $nickname.' 欢迎使用后台管理系统',
                        'color' => '#63b359'
                    ),
                    'name' => array(
                        'value' => $data['name'],
                        'color' => '#509fc9'
                    ),
                    'pjname' => array(
                        'value' => $data['pjname'],
                        'color' => '#cc463d'
                    ),
                    'ptime' => array(
                        'value' => $data['ptime'],
                        'color' => '#509fc9'
                    ),
                    'paddress' => array(
                        'value' => $data['paddress'],
                        'color' => '#509fc9'
                    ),
                    'pltime' => array(
                        'value' => $data['pltime'],
                        'color' => '#509fc9'
                    ),
                    'remark' => array(
                        'value' => '请注意密码安全，谢谢您的使用',
                        'color' => '#2c9f67'
                    )
                );
            $data = $tmp;
        }
        $data = array(
                    "touser" => $openid,
                    "template_id" => $templateId,
                    //"url"=>"http://www.baidu.com",
                    'data' => $data
                );
        $token = $this->getToken();
        $url = 'https://api.weixin.qq.com/cgi-bin/message/template/send?access_token='.$token;
        $data = json_encode($data);

        $this->httpCurl($url,'post','arr',$data);
    }

    public function mylog($content)
    {
        if ( is_array($content) ) {
            $content = print_r($content,true);
        }
        M('log')->data(['content'=>$content])->add();
    }


    /**
     * 上传卡券logo
     * @param  string $file jpg图片的path或url
     * @return [type]       [description]
     */
    public function uploadLogo($file)
    {
        $this->checkImg($file);

        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/cgi-bin/media/uploadimg?access_token=".$token;

        $data = array('media'=>'@'.$file);

        $res = $this->httpCurl($url,'post','arr',$data);

        if ( isset($res['errcode']) ) {
            return $res['errcode'];
        }
        return $res['url'];
    }


    /**
     * 创建卡券，并返回card_id
     * @param  [type] $op [description]
     * @return [type]     [description]
     */
    public function createCard($op)
    {
        $logo_url = $this->uploadLogo($op['logo_url']);
        $brand_name = $op['brand_name'];
        $code_type = $op['code_type'];
        $title = $op['title'];
        $color = $op['color'];
        $notice = $op['notice'];
        $service_phone = $op['service_phone'];
        $description = $op['description'];
        $date_info = $op['date_info'];
        $sku = $op['sku'];
        $base_info = new BaseInfo( $logo_url, $brand_name,
                $code_type, $title, $color, $notice, $service_phone,
                $description, new DateInfo($date_info[0], $date_info[1], $date_info[2]), new Sku($sku) );
        $base_info->set_sub_title( "" );  //
        $base_info->set_use_limit( 1 );
        $base_info->set_get_limit( 3 );
        $base_info->set_use_custom_code( false );
        $base_info->set_bind_openid( false );
        $base_info->set_can_share( true );
        $base_info->set_url_name_type( 1 );
        $base_info->set_custom_url( "http://www.baidu.com" );
        //---------------------------set_card--------------------------------

        if ( isset($op['deal_detail']) ) {
            // 团购券
            $card_type = "GROUPON";
            $card = new Card($card_type, $base_info);
            $card->get_card()->set_deal_detail( $op['deal_detail'] );

        } elseif ( isset($op['least_cost']) ) {
            $card_type = "CASH";
            $card = new Card($card_type, $base_info);
            $card->get_card()->set_least_cost( $op['deal_detail'] );
            $card->get_card()->set_reduce_cost( $op['reduce_cost'] );

        } elseif ( isset($op['discount']) ) {
            $card_type = "DISCOUNT";
            $card = new Card($card_type, $base_info);
            $card->get_card()->set_discount( $op['discount'] );

        } elseif ( isset($op['gift']) ) {
            $card_type = "GIFT";
            $card = new Card($card_type, $base_info);
            $card->get_card()->set_gift($op['gift']);
        } else {
            $card_type = "GENERAL_COUPON";
            $card = new Card($card_type, $base_info);
            $card->get_card()->set_default_detail( $op['default_detail'] );
        }

        //--------------------------to json--------------------------------
        $jsonStr =  $card->toJson();

        //--------------------------post 方式创建卡券--------------------------------
        $token = $this->getToken();
        $url = "https://api.weixin.qq.com/card/create?access_token=".$token;

        $data = $this->httpCurl($url,'post','arr',$jsonStr);

        if ( $data['errcode'] == 0 ) {
            return $data['card_id'];
        } else {
            return $data['errcode'];
        }
    }

    /**
     * 通过card_id获取card二维码
     * @param  string $card_id [description]
     * @return [type]          [description]
     */
    public function getCardQRCode($card_id='p4fDD0liiNQMViCPO50EIDUS0jR0')
    {
        $token = $this->getToken();
        $url = "https://api.weixin.qq.com/card/qrcode/create?access_token=".$token;

        $jsonStr = '{
                        "action_name": "QR_CARD",
                        "action_info": {
                            "card": {
                                "card_id": "'.$card_id.'"
                            }
                        }
                    }';

        $res = $this->httpCurl($url,'post','arr',$jsonStr);

        if ( $res['errcode'] == 0 ) {
            return $res['show_qrcode_url'];
        } else {
            return false;
        }
    }

    public function addTestUser($users=[])
    {
        $jsonStr = json_encode($users);
        $jsonStr = '{ "username":'.$jsonStr.' }';

        $token = $this->getToken();

        $url = "https://api.weixin.qq.com/card/testwhitelist/set?access_token=".$token;

        $res = $this->httpCurl($url,'post','arr',$jsonStr);
        if ( $res['errcode'] == 0 ) {
            return $res['success_username'];
        } else {
            return false;
        }

    }

    public function checkCardCode($code,$card_id)
    {
        $token = $this->getToken();
        $url = "https://api.weixin.qq.com/card/code/get?access_token=".$token;

        $jsonStr = '{
                       "card_id" : "'.$card_id.'",
                       "code" : "'.$code.'",
                       "check_consume" : false
                    }';

        $data = $this->httpCurl($url,'post','arr',$jsonStr);
        $can_consume = $data['can_consume'];

        if ( $can_consume ) {
            //可以消费
            //return true;
            return $data;
        } else {
            return $data;
        }

    }

    public function consumeCard($code,$card_id=false)
    {
        if ( !$card_id ) {
            // 微信分配code
            $jsonStr = '{ "code": "'.$code.'" }';
        } else {
            //自定义code
            $jsonStr = '{
                          "code": "'.$code.'",
                          "card_id": "'.$card_id.'"
                        }';
        }

        $token = $this->getToken();
        $url = "https://api.weixin.qq.com/card/code/consume?access_token=".$token;

        $data = $this->httpCurl($url,'post','arr',$jsonStr);
        if ( $data['errcode'] != 0 ) {
            // 出错
        } else {
            //成功
            $card_id = $data['card']['card_id'];
            $openid = $data['openid'];

        }
        return $data;
    }


    public function getCards()
    {
        $url = "https://api.weixin.qq.com/card/code/get?access_token=";
    }


    /**
     * 微信卡券跳转的code decryptCode
     * @return [type] [description]
     */
    public function decryptCode()
    {

        $wechat = new WeChat();
        $token = $wechat->getToken();

        $url = "https://api.weixin.qq.com/card/code/decrypt?access_token={$token}";

        $encrypt_code = I('encrypt_code','','urldecode');

        $jsonStr = '{
                      "encrypt_code":"'.$encrypt_code.'"
                    }';


        $data = $this->httpCurl($url,'post','arr',$jsonStr);

        if ( $data['errcode'] == 0 ) {
            return $data['code'];
        } else {
            return false;
        }
    }


}

