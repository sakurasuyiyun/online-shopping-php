<?php
declare (strict_types = 1);

namespace app\middleware;

use think\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use think\Response;

class CorsMiddleware
{
    /**
     * 处理请求
     *
     * @param \think\Request $request
     * @param \Closure       $next
     * @return Response
     */

    public function handle(Request $request, \Closure $next)
    {
        // 跨域请求
        header("Access-Control-Allow-Origin:*");
        // 允许的请求方法
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
        // 允许的请求头
        header("Access-Control-Allow-Headers: Content-Type, Authorization");

        if ($request->isOptions()) {
            return json([], 200, [
                'Access-Control-Allow-Origin' => '*',
                'Access-Control-Allow-Methods' => 'GET, POST',
                'Access-Control-Allow-Headers' => 'Authorization',
                'Access-Control-Allow-Credentials' => 'true',
                'Access-Control-Max-Age' => 86400,
            ]);
        }

        // 获取 Authorization 请求头
        $authorizationHeader = $request->header('Authorization');

        if(empty($authorizationHeader)){
            $authorizationHeader = '';
        }

        $token = str_replace('Bearer ', '', $authorizationHeader);

        $checkAuthorization = $this->checkAuthorization($token);

        $path = $_SERVER['PATH_INFO']; // 获取当前请求的路径

        if (preg_match('/public\//', $path)){
            return $next($request);
        }else{
            if($checkAuthorization['errcode'] != 0){
                return Response::create(['errcode' => $checkAuthorization['errcode'], 'message' => $checkAuthorization['message']], 'json', 200);
            }else{
                $request->user_id = $checkAuthorization['user_id'];
                return $next($request);
            }
        }

        // return $next($request);
    }

    public function checkAuthorization($token)
    {
        // 判断cookie中的token是否为空,不为空才往下执行
        if (!empty ($token)) {

            // 获取密钥
            $secretKey = config('jwt.secret_key');

            try {
                // 解码 Token
                $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));

                $user_id = $decoded->user_id;

                // 返回验证结果或进行其他处理
                return [
                    'errcode' => 0,
                    'message' => 'Token 验证成功',
                    'user_id' => $user_id
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
}
