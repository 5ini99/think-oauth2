<?php
// +----------------------------------------------------------------------
// | thinkphp5 Oauth2 [ WE CAN DO IT JUST THINK IT ]
// +----------------------------------------------------------------------
// | Copyright (c) 2016 http://www.zzstudio.net All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: Byron Sampson <xiaobo.sun@qq.com>
// +----------------------------------------------------------------------
namespace think;

use think\Db;
use think\Config;
use think\Loader;
use think\oauth2\Server;

// OAUTH2_DB_DSN  数据库连接DSN
// OAUTH2_CODES_TABLE 服务器表名称
// OAUTH2_CLIENTS_TABLE 客户端表名称
// OAUTH2_TOKEN_TABLE 验证码表名称
/**
 * -------------------------------------------------------------
 * CREATE TABLE `oauth_client` (
 * `id` bigint(20) NOT NULL auto_increment,
 * `client_id` varchar(32) NOT NULL,
 * `client_secret` varchar(32) NOT NULL,
 * `redirect_uri` varchar(200) NOT NULL,
 * `create_time` int(20) default NULL,
 * PRIMARY KEY  (`id`)
 * ) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
 *
 * CREATE TABLE `oauth_code` (
 * `id` bigint(20) NOT NULL auto_increment,
 * `client_id` varchar(32) NOT NULL,
 * `user_id` varchar(32) NOT NULL,
 * `code` varchar(40) NOT NULL,
 * `redirect_uri` varchar(200) NOT NULL,
 * `expires` int(11) NOT NULL,
 * `scope` varchar(250) default NULL,
 * PRIMARY KEY  (`id`)
 * ) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
 *
 * CREATE TABLE `oauth_token` (
 * `id` bigint(20) NOT NULL auto_increment,
 * `client_id` varchar(32) NOT NULL,
 * `user_id` varchar(32) NOT NULL,
 * `access_token` varchar(40) NOT NULL,
 * `refresh_token` varchar(40) NOT NULL,
 * `expires` int(11) NOT NULL,
 * `scope` varchar(200) default NULL,
 * PRIMARY KEY  (`id`)
 * ) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
 */
class Oauth2 extends Server
{
    /**
     * @var object 对象实例
     */
    protected static $instance;

    // 数据库对象
    protected $db = null;
    // 配置信息
    protected $config = [
        'auth_codes' => "oauth_code",   // code码记录表
        'clients' => "oauth_client",    // client客户端
        'tokens' => "oauth_token",      // token生成表
    ];
    // 数据表前缀
    protected $prefix = "";
    // 需要操作的数据表
    protected $table = [];
    // 错误信息
    protected $error;

    // Hook扩展方法
    protected static $hook = [];

    /**
     * 类初始化
     */
    protected function init()
    {
        if ($oauth2 = Config::get('oauth2')) {
            $this->config = array_merge($this->config, $oauth2);
        }
        // 查看是否配置表前缀
        $prefix = Config::get('database.prefix');
        $allow = ['auth_codes', 'clients', 'tokens'];
        foreach ($this->config as $key => $table) {
            if (in_array($key, $allow)) {
                // 转换表名
                $this->table[$key] = "{$prefix}{$table}";
            }
        }
    }

    /**
     * 魔术call
     * @param $method
     * @param $args
     * @return mixed
     * @throws Exception
     */
    public function __call($method, $args)
    {
        if (array_key_exists($method, self::$hook)) {
            array_unshift($args, $this);
            return call_user_func_array(self::$hook[$method], $args);
        } else {
            throw new Exception('method not exists:' . __CLASS__ . '->' . $method);
        }
    }

    /**
     * Hook 方法注入
     * @access public
     * @param string|array $method 方法名
     * @param mixed $callback callable
     * @return void
     */
    public static function hook($method, $callback = null)
    {
        if (is_array($method)) {
            self::$hook = array_merge(self::$hook, $method);
        } else {
            self::$hook[$method] = $callback;
        }
    }

    /**
     * 初始化
     * @access public
     * @param $config
     * @return \think\Oauth2
     */
    public static function instance($config = [])
    {
        if (is_null(self::$instance)) {
            self::$instance = new static($config);
        }
        return self::$instance;
    }

    /**
     *
     * 增加client
     * @param string $client_id
     * @param string $client_secret
     * @param string $redirect_uri
     * @return int|string
     */
    public function addClient($client_id, $client_secret, $redirect_uri)
    {
        $data = [
            'client_id' => $client_id,
            'client_secret' => $client_secret,
            'redirect_uri' => $redirect_uri,
            'create_time' => NOW_TIME
        ];

        return Db::table($this->table['clients'])->insert($data, false, true);
    }

    /**
     * Implements OAuth2::checkClientCredentials()
     * @see OAuth2::checkClientCredentials()
     */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        $result = Db::table($this->table['clients'])->field('client_secret')->where('client_id',
            $client_id)->find();
        if ($client_secret === null) {
            return $result !== false;
        }

        return is_array($result) ? ($result["client_secret"] == $client_secret) : false;
    }

    /**
     * 获取客户端信息
     * @param $client_id
     * @return array|false|mixed|\PDOStatement|string|\think\Model
     */
    public function getClientInfo($client_id)
    {
        $result = cache('OAUTH2:CLIENT:' . $client_id);
        if (empty($result)) {
            $result = Db::table($this->table['clients'])->where('client_id', $client_id)->find();
            isset($result['extra']) && $result['extra'] = json_decode($result['extra'], true);
            is_array($result) && cache('OAUTH2:CLIENT:' . $client_id, $result);
        }

        return $result;
    }

    /**
     * Implements OAuth2::getRedirectUri().
     * @param $client_id
     * @see OAuth2::getRedirectUri()
     * @return bool|null
     */
    public function getRedirectUri($client_id)
    {
        $result = Db::table($this->table['clients'])->field('redirect_uri')->where('client_id',
            $client_id)->find();
        if ($result === false) {
            return false;
        }

        return isset($result["redirect_uri"]) && $result["redirect_uri"] ? $result["redirect_uri"] : null;
    }

    /**
     * Implements OAuth2::getAccessToken().
     * @param $access_token
     * @see OAuth2::getAccessToken()
     * @return mixed|null
     */
    public function getAccessToken($access_token)
    {
        $result = Db::table($this->table['tokens'])
            ->field('client_id, user_id, expires, scope')
            ->where('access_token', $access_token)
            ->master()
            ->find();

        return is_array($result) ? $result : null;
    }

    /**
     * Implements OAuth2::setAccessToken().
     * @see OAuth2::setAccessToken()
     */
    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null)
    {
        $time = time();
        // 如果存在用户认证信息则删除后重新生成
        if ($user_id > 0) {
            $data = Db::table($this->table['tokens'])->where([
                'client_id' => $client_id,
                'user_id' => $user_id
            ])->find();
            is_array($data) && cache("ACCESS:TOKEN:{$data['access_token']}", null);
        }

        // 将当前记录记入缓存，用于token失效时及时获取token对应的用户uid
        cache("TOKEN:{$access_token}", ['uid' => $user_id, 'client_id' => $client_id, 'create_time' => $time],
            OAUTH2_DEFAULT_ACCESS_TOKEN_LIFETIME);

        // 生成token信息
        $data['access_token'] = $access_token;
        $data['user_id'] = $user_id;
        $data['client_id'] = $client_id;
        $data['expires'] = $expires;
        $data['scope'] = $scope;
        $data['client_ip'] = get_client_ip();
        $data['create_time'] = $time;

        Db::table($this->table['tokens'])->insert($data, true);
    }

    /**
     * Implements OAuth2::getSupportedGrantTypes()
     * @see OAuth2::getSupportedGrantTypes()
     */
    public function getSupportedGrantTypes()
    {
        return [
            OAUTH2_GRANT_TYPE_AUTH_CODE,
            OAUTH2_GRANT_TYPE_REFRESH_TOKEN,
            OAUTH2_GRANT_TYPE_USER_CREDENTIALS,
            OAUTH2_GRANT_TYPE_ASSERTION,
            OAUTH2_GRANT_TYPE_NONE,
        ];
    }

    /**
     * Implements OAuth2::getRefreshToken()
     * @param $refresh_token
     * @see OAuth2::getRefreshToken()
     * @return null
     */
    public function getRefreshToken($refresh_token)
    {
        // 获取tokens基础信息
        $result = Db::table($this->table['tokens'])
            ->field('id, client_id, user_id, refresh_token, expires, scope')
            ->where('refresh_token', $refresh_token)
            ->find();

        /*// 当用户信息存在
        if(is_array($result)){
            Db::table($this->table['tokens'])->where('id', $result['id'])->delete();
            return $result;
        }*/

        return is_array($result) ? $result : null;
    }

    /**
     * Implements OAuth2::setRefreshToken()
     * @param $refresh_token
     * @param $client_id
     * @param $user_id
     * @param $expires
     * @param null $scope
     * @see OAuth2::setRefreshToken()
     * @return bool
     */
    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null)
    {
        if (0 == $user_id) {
            return false;
        }
        $data = [
            'refresh_token' => $refresh_token,
            'expires' => $expires,
            'scope' => $scope
        ];

        return Db::table($this->table['tokens'])->where([
            'client_id' => $client_id,
            'user_id' => $user_id
        ])->update($data);
    }

    /**
     * Overrides OAuth2::getAuthCode().
     * @see OAuth2::getAuthCode()
     */
    public function getAuthCode($code)
    {
        return Db::table($this->table['auth_codes'])
            ->field('code, client_id, user_id, redirect_uri, expires, scope')
            ->where('code', $code)
            ->master()
            ->find();
    }

    /**
     * Overrides OAuth2::setAuthCode().
     * @see OAuth2::setAuthCode()
     */
    public function setAuthCode($code, $client_id, $redirect_uri, $expires, $scope = null)
    {
        $data = [
            'code' => $code,
            'client_id' => $client_id,
            'user_id' => is_login(),
            'redirect_uri' => $redirect_uri,
            'expires' => $expires,
            'scope' => $scope,
            'create_time' => time()
        ];
        Db::table($this->table['auth_codes'])->insert($data);
    }

    /**
     * 检查用户名密码是否异常
     * Overrides OAuth2::checkUserCredentials().
     * @see OAuth2::checkUserCredentials()
     */
    public function checkUserCredentials($client_id, $username, $password)
    {
        return true;
    }

    /**
     * 检查当前用户是否已登录
     * @param $client_id
     * @param $user_id
     * @return array
     */
    public function checkUserLogin($client_id, $user_id)
    {
        $result = Db::table($this->table['tokens'])
            ->field('access_token, user_id, refresh_token, expires, client_ip, create_time, scope')
            ->where(['client_id' => $client_id, 'user_id' => $user_id])
            ->find();

        return is_array($result) ? $result : false;
    }

    /**
     * 检测access_token是否有效
     * @param null $access_token
     * @return bool|mixed
     */
    public function checkAccessToken($access_token = null)
    {
        //$info = cache("ACCESS:TOKEN:{$access_token}") ?: $this->getAccessToken($access_token);
        $info = $this->getAccessToken($access_token);
        if (is_null($info)) {
            $this->error = 'access_token not exists';
            return false;
        } else {
            if (isset($info['expires']) && $info['expires'] < time()) {
                $this->error = 'access_token expired';
                return false;
            }
        }
        empty($info) or cache("ACCESS:TOKEN:{$access_token}", $info, $info['expires'] - time());

        return $info;
    }

    /**
     * 断言判断
     * @param $client_id
     * @param $assertion_type
     * @param $assertion
     * @return bool
     */
    protected function checkAssertion($client_id, $assertion_type, $assertion)
    {
        return false;
    }

    /**
     * Grant access tokens for the "none" grant type.
     *
     * Not really described in the IETF Draft, so I just left a method
     * stub... Do whatever you want!
     *
     * Required for OAUTH2_GRANT_TYPE_NONE.
     *
     * @ingroup oauth2_section_4
     */
    protected function checkNoneAccess($client_id)
    {
        global $user_id;
        $data['user_id'] = $user_id;
        return $data;
    }

    /**
     * 获取错误详情
     * @return mixed
     */
    public function getError()
    {
        return $this->error;
    }
}
