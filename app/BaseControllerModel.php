<?php
declare(strict_types=1);

namespace app;

use think\facade\Cache;
use think\facade\Log;
use app\model\UsersModel;

/**
 * 控制器基础类
 */
class BaseControllerModel
{
    protected $redis;

    protected $usersModel;

    public function __construct()
    {
        $this->redis = $this->getRedisCache();

        $this->usersModel = new UsersModel();
    }

    protected function getRedisCache()
    {
        $redis = Cache::store('redis');
        
        return $redis;
    }

}
