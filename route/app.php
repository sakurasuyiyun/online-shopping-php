<?php
// +----------------------------------------------------------------------
// | ThinkPHP [ WE CAN DO IT JUST THINK ]
// +----------------------------------------------------------------------
// | Copyright (c) 2006~2018 http://thinkphp.cn All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: liu21st <liu21st@gmail.com>
// +----------------------------------------------------------------------
use think\facade\Route;

Route::get('think', function () {
    return 'hello,ThinkPHP6!';
});

// 公共接口
Route::post('api/public/login', 'api/login');
Route::post('api/public/register', 'api/register');
Route::get('api/public/product_list', 'api/productList');
Route::get('api/public/getUserInfo', 'api/getUserInfo');

// 授权接口
Route::get('api/secret/getUserInfo', 'api/getUserInfo');
Route::post('api/secret/changeLoginPwd', 'api/changeLoginPwd');
Route::post('api/secret/changePhoneNumber', 'api/changePhoneNumber');
Route::post('api/secret/sendCode', 'api/sendCode');
Route::post('api/secret/changePayPwd', 'api/changePayPwd');

// 测试接口
Route::get('api/public/test', 'api/test');