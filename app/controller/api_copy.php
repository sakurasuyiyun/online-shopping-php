<?php
declare(strict_types=1);

namespace app\controller;

use think\Request;
use think\facade\Db;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// use think\cache\driver\Redis as DriverRedis;
// use think\facade\Log;
// use PhpOffice\PhpSpreadsheet\Spreadsheet;
// use PhpOffice\PhpSpreadsheet\IOFactory;

class api
{
    public function __construct()
    {
        // 跨域请求
        header("Access-Control-Allow-Origin:*");
    }

    public function login(Request $request)
    {
        $email = $request->param('email');
        $password = $request->param('password');
        $ip = $request->ip();

        if (empty($email)) {
            echo json_encode([
                "errno" => 1,
                "msg" => "用户邮箱不能为空",
            ]);
            exit;
        }

        if (empty($password)) {
            echo json_encode([
                "errno" => 1,
                "msg" => "密码不能为空",
            ]);
            exit;
        }

        $check = Db::name("users")->where("email", "=", $email)->find();

        if (empty($check)) {
            echo json_encode([
                "errno" => 1,
                "msg" => "该用户不存在",
            ]);
            exit;
        }

        if ($check['password'] === md5($password) && $check['email'] === $email) {

            $update = Db::name('users')->where('email', '=', $email)->update([
                'last_login' => date("Y-m-d H:i:s"),
                'ip' => $ip
            ]);

            // 数据载荷
            $payload = [
                'iss' => 'sakura_chat',  // 令牌的发行者
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
            $expire = time() + 28800 + 3600 * 24;

            // 在服务器端设置 Cookie
            setcookie('token', $jwtToken, $expire, '/', '1.12.73.162', false, true);

            echo json_encode([
                'errno' => 0,
                'msg' => '登陆成功，欢迎回来',
                'token' => $jwtToken,
            ]);
            exit;
        }
    }

    public function register(Request $request)
    {
        $username = $request->param('username');
        $email = $request->param('email');
        $password = $request->param('password');
        $confirmPassword = $request->param('confirmPassword');

        if (empty($username)) {
            echo json_encode([
                "errno" => 1,
                "msg" => "用户名不能为空",
            ]);
            exit;
        }

        if (empty($email)) {
            echo json_encode([
                "errno" => 1,
                "msg" => "用户邮箱不能为空",
            ]);
            exit;
        }

        if (empty($password)) {
            echo json_encode([
                "errno" => 1,
                "msg" => "密码不能为空",
            ]);
            exit;
        }

        if (empty($confirmPassword)) {
            echo json_encode([
                "errno" => 1,
                "msg" => "确认密码不能为空",
            ]);
            exit;
        }

        if ($password !== $confirmPassword) {
            echo json_encode([
                "errno" => 1,
                "msg" => "两次密码输入不一致",
            ]);
            exit;
        }

        $grep = '/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/';

        if (!preg_match($grep, $email)) {
            echo json_encode([
                "errno" => 1,
                "msg" => "邮箱格式不正确",
            ]);
            exit;
        }

        $data = [
            "username" => $username,
            "email" => $email,
            "password" => md5($password),
            "createtime" => date("Y-m-d H:i:s"),
            "last_login" => "0000-00-00 00:00:00"
        ];

        $check = Db::name("users")->where("email", "=", $email)->find();

        if (!empty($check)) {
            echo json_encode([
                "errno" => 1,
                "msg" => "该账号已存在，请勿重复注册",
            ]);
            exit;
        }

        $insert = Db::name("users")->save($data);

        if (empty($insert)) {
            echo json_encode([
                "errno" => 1,
                "msg" => "注册失败",
            ]);
            exit;
        }

        echo json_encode([
            "errno" => 0,
            "msg" => "注册成功"
        ]);
        exit;
    }

    public function checkToken(Request $request)
    {
        $token = $request->param("token");

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
                echo json_encode([
                    'errno' => 0,
                    'message' => 'Token 验证成功',
                    'data' => [
                        'username' => $username,
                        'user_id' => $user_id
                    ]
                ]);
                exit;
            } catch (\Exception $e) {
                // 验证失败，可能是 Token 无效或过期
                // 返回错误信息或进行其他处理
                echo json_encode([
                    'errno' => 1,
                    'message' => 'Token 验证失败'
                ]);
                exit;
            }
        } else {
            echo json_encode([
                'errno' => 1,
                'message' => 'Token 为空'
            ]);
            exit;
        }
    }
}
