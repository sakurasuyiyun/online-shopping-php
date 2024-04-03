<?php
declare(strict_types=1);

namespace app\controller;

use think\Request;
use think\facade\Db;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// use app\BaseControllerModel;
use app\model\UsersModel;

// use think\cache\driver\Redis as DriverRedis;
// use think\facade\Log;
// use PhpOffice\PhpSpreadsheet\Spreadsheet;
// use PhpOffice\PhpSpreadsheet\IOFactory;

class api
{
    protected $middleware = ['cors'];
    // protected $usersModel;

    public function __construct(Request $request)
    {
        // parent::__construct();

        $this->usersModel = new UsersModel();

        // $this->redis = new \Redis();
        // $this->redis->connect('localhost', 6379);
    }

    public function login(Request $request)
    {
        $username = $request->param('username');
        $password = $request->param('password');
        $ip = $request->ip();

        if (empty($username)) {
            return [
                "errcode" => 40001,
                "msg" => "手机号不能为空",
            ];
        }

        if (empty($password)) {
            return [
                "errcode" => 40001,
                "msg" => "密码不能为空",
            ];
        }

        $check = Db::name("users")->where(["username" => $username])->find();

        if (empty($check)) {
            $res = $this->register($request);

            if ($res['errcode'] != 0) {
                return $res;
            }

            $check = Db::name("users")->where(["username" => $username])->find();
        }

        if ($check['password'] === md5($password) && $check['username'] === $username) {

            $update = Db::name('users')->where(["username" => $username])->update([
                'last_login' => date("Y-m-d H:i:s"),
                'ip' => $ip
            ]);

            // 数据载荷
            $payload = [
                'iss' => 'online_shopping',  // 令牌的发行者
                'username' => $check['username'],  // 用户名
                'nbf' => time(), // 令牌的生效时间,
                'exp' => time() + 3600 * 24, //令牌的过期时间
                'user_id' => $check['user_id'] // 用户id
            ];

            // 获取密钥
            $secretKey = config('jwt.secret_key');

            // 设置token唯一标识符
            $kid = 'login';

            // 生成token
            $jwtToken = JWT::encode($payload, $secretKey, "HS256", $kid);

            // 设置token过期时间
            // $expire = time() + 28800 + 3600 * 24;

            // 在服务器端设置 Cookie
            // setcookie('token', $jwtToken, $expire, '/', '127.0.0.1', false, true);

            return [
                'errcode' => 0,
                'msg' => '登陆成功，欢迎回来',
                'token' => 'Bearer ' . $jwtToken,
            ];
        } else {
            return [
                'errcode' => 40005,
                'msg' => '账号或密码错误',
            ];
        }
    }

    public function register($request)
    {
        $username = $request->param('username');
        $password = $request->param('password');

        if (empty($username)) {
            return [
                "errcode" => 40001,
                "msg" => "手机号不能为空",
            ];
        }

        if (empty($password)) {
            return [
                "errcode" => 40001,
                "msg" => "密码不能为空",
            ];
        }

        $grep = '/^(?:(?:\+|00)86)?1(?:(?:3[\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\d])|(?:9[1589]))\d{8}$/';

        if (!preg_match($grep, $username)) {
            return [
                "errcode" => 40003,
                "msg" => "手机号格式不正确",
            ];
        }

        $data = [
            "username" => $username,
            "password" => md5($password),
            "createtime" => date("Y-m-d H:i:s"),
            "usernickname" => "商城用户" . substr($username, -4),
            "user_id" => time() . substr($username, -2),
            "pay_password" => md5("888888")
        ];

        $check = Db::name("users")->where("username", "=", $username)->find();

        if (!empty($check)) {
            return [
                "errcode" => 40002,
                "msg" => "该账号已存在，请勿重复注册",
            ];
        }

        $insert = Db::name("users")->save($data);

        if (empty($insert)) {
            return [
                "errcode" => 40004,
                "msg" => "注册失败",
            ];
        }

        return [
            "errcode" => 0,
            "msg" => "注册成功"
        ];
    }

    public function checkAuthorization($token)
    {
        // 判断cookie中的token是否为空,不为空才往下执行
        if (!empty($token)) {

            // 获取密钥
            $secretKey = config('jwt.secret_key');

            try {
                // 解码 Token
                $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));

                // 验证成功，可以根据需要获取 Token 中的数据
                $username = $decoded->username;
                $user_id = $decoded->user_id;
                // 其他操作...

                // 返回验证结果或进行其他处理
                return [
                    'errcode' => 0,
                    'message' => 'Token 验证成功',
                    'data' => [
                        'username' => $username,
                        'user_id' => $user_id
                    ]
                ];
            } catch (\Exception $e) {
                // 验证失败，可能是 Token 无效或过期
                // 返回错误信息或进行其他处理
                return [
                    'errcode' => 50002,
                    'message' => '用户登录信息已过期'
                ];
            }
        } else {
            return [
                'errcode' => 50001,
                'message' => '用户尚未登录'
            ];
        }
    }

    public function productList(Request $request)
    {
        // return [
        //     [
        //         "id" => 1
        //     ],
        //     [
        //         "id" => 2
        //     ],
        //     [
        //         "id" => 3
        //     ]
        // ];

        echo json_encode(
            [
                [
                    "id" => 1
                ],
                [
                    "id" => 2
                ],
                [
                    "id" => 3
                ]
            ]
        );
        exit;
    }

    // 获取用户信息
    public function getUserInfo(Request $request)
    {
        // 获取 Authorization 请求头
        $authorizationHeader = $request->header('Authorization');

        if (empty($authorizationHeader)) {
            return ["errcode" => 40005, "msg" => "未登录"];
        }

        // Authorization 请求头的格式通常是 Bearer token，所以你可能需要解析出 token 部分
        $token = str_replace('Bearer ', '', $authorizationHeader);
        // 现在 $token 中包含了认证令牌，你可以在这里进行后续处理
        // 例如：验证认证令牌是否有效，检查用户权限等
        $res = $this->checkAuthorization($token);

        if ($res['errcode'] != 0) {
            return $res;
        }

        $data = $res['data'];

        $where = [
            "user_id" => $data['user_id']
        ];

        // 调用自定义方法进行条件查询
        $field = "username, usernickname, user_id, email";

        $user_info = $this->usersModel->getRow($field, $where);

        if (empty($user_info)) {
            return [
                "errcode" => 40006,
                "msg" => "查询用户信息为空",
            ];
        }

        return [
            "errcode" => 0,
            "msg" => "获取数据成功",
            "data" => $user_info
        ];
    }

    // 修改登录密码
    public function changeLoginPwd(Request $request)
    {
        $old_pwd = $request->param("oldPwd");
        $new_pwd = $request->param("newPwd");
        $user_id = $request->user_id;

        $user_info = $this->usersModel->getRow("user_id, password", ['user_id' => $user_id]);

        if (md5($old_pwd) != $user_info['password']) {
            return [
                "errcode" => 40005,
                "msg" => "旧密码错误"
            ];
        }

        if ($old_pwd == $new_pwd) {
            return [
                "errcode" => 40005,
                "msg" => "旧密码和新密码相同"
            ];
        }

        $update = $this->usersModel->updateUser(['user_id' => $user_id], ['password' => md5($new_pwd)]);

        if (empty($update)) {
            return [
                "errcode" => 40005,
                "msg" => "修改失败"
            ];
        }

        return [
            "errcode" => 0,
            "msg" => "修改成功"
        ];
    }

    // 修改手机号
    public function changePhoneNumber(Request $request)
    {
        $phone = $request->param("phone");
        $pay_pwd = $request->param("pwd");
        $user_id = $request->user_id;

        // 校验支付密码
        $user_info = $this->usersModel->getRow("user_id, pay_password, username", ['user_id' => $user_id]);

        if (md5($pay_pwd) != $user_info['pay_password']) {
            return [
                "errcode" => 40005,
                "msg" => "支付密码密码错误"
            ];
        }

        if ($user_info['username'] == $phone) {
            return [
                "errcode" => 40005,
                "msg" => "旧号码和新号码相同"
            ];
        }

        // 查询该手机号是否被注册
        $check = $this->usersModel->getRow("user_id, username", ['username' => $phone]);

        if (!empty($check)) {
            return [
                "errcode" => 40005,
                "msg" => "该手机号已被注册"
            ];
        }

        $update = $this->usersModel->updateUser(['user_id' => $user_id], ['username' => $phone]);

        if (empty($update)) {
            return [
                "errcode" => 40005,
                "msg" => "修改失败"
            ];
        }

        return [
            "errcode" => 0,
            "msg" => "修改成功"
        ];
    }

    // 发送验证码
    public function sendCode(Request $request)
    {
        $user_id = $request->user_id;

        // $check = $this->redis->get($user_id);

        // if(!empty($check)){
        //     return [
        //         "errcode" => 1,
        //         "msg" => "请不要频繁获取验证码"
        //     ]; 
        // }

        // 生成一个随机的 6 位数
        $code = intval(mt_rand(100000, 999999));

        $this->redis->setex($user_id, 300, '您的验证码是：' . $code);

        return [
            "errcode" => 0,
            "msg" => "发送成功",
            "data" => "验证码是：" . $code
        ];
    }

    public function changePayPwd(Request $request)
    {
        $user_id = $request->user_id;


    }

    public function test(Request $request)
    {
        $request->user_id = 888888888888;
        dd($request->user_id);
    }
}
